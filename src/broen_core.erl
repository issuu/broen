%%% ---------------------------------------------------------------------------------
%%% @doc
%%% broen_core turns HTTP requests/responses into AMQP RPC messaging.
%%% Given a HTTP Request, this module will first authenticate it using the provided
%%% authentication plugin and the publish the message serialized with the serializer
%%% plug over AMQP. Upon receiving a response, the module will respond back over HTTP.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_core).


-export([handle/4]).
-export([register_metrics/0]).
-export([stringdate_to_datetime/1]).
-define(CLIENT_REQUEST_BODY_LIMIT, 65536).
-define(DEFAULT_TIMEOUT, 20). % secs
-define(ACAO_HEADER, <<"access-control-allow-origin">>).

-type content_type() :: unicode:unicode_binary().
%% The MIME content type
-type broen_string() :: unicode:unicode_binary().
%% A binary string
-type broen_nullable_string() :: unicode:unicode_binary() | null.
%% A binary string that can be null
-type broen_object() :: #{broen_string() => broen_string()}.
%% An generic sub-object that is a map mapping a string to a string. Used for e.g. HTTP headers

-type cookie_name() :: broen_string().
%% The name of a cookie
-type cookie_value() :: #{
value := broen_string(),
domain => broen_string(),
path => broen_string(),
http_only => boolean(),
secure => boolean(),
expires => broen_string()}.
%% The cookie properties. Each cookie must define a value and may optionally define the domain it applies to and the expiration date
-type broen_cookies() :: #{cookie_name() => cookie_value()}.
%% The cookies object maps cookie names to the properties.

-type broen_request() :: #{
appmoddata := broen_string(),
protocol := http | https,
cookies := broen_object(),
http_headers := broen_object(),
request := broen_string(),
method := broen_string(),
referer := broen_nullable_string(),
fullpath := broen_string(),
useragent := broen_nullable_string(),
client_data := binary() | null,
client_ip := broen_string(),
routing_key := broen_string(),
queryobj := broen_object(),
auth_data := term(),
querydata => broen_string(),
postobj => broen_object(),
multipartobj => term()}.
%
%
% }.
%% The format of a broen request that is sent to the serializer plugin. <br/>
%% <b>cookies</b> - Cookies attached to the HTTP request <br/>
%% <b>http_headers</b> - HTTP request headers <br/>
%% <b>request</b> - The HTTP method <br/>
%% <b>method</b> - Same as above <br/>
%% <b>client_data</b> - Client information <br/>
%% <b>fullpath</b> - Full path of the request as provided by Yaws <br/>
%% <b>appmoddata</b> - The URL that is turned into the routing key (i.e. what follows /call) <br/>
%% <b>referer</b> - The referer URL <br/>
%% <b>useragent</b> - User agent data <br/>
%% <b>client_ip</b> - IP of the client <br/>
%% <b>routing_key</b> - The routing key the request will be sent to <br/>
%% <b>queryobj</b> - The query object containing the query parameters <br/>
%% <b>auth_data</b> - Data returned by the authentication module <br/>
%% <b>querydata</b> - Same as queryobj, but in a string format <br/>
%% <b>postobj</b>- Data attached to a POST request <br/>
%% <b>multipartobj</b> - Data for the multipart request <br/>

-type broen_response() :: #{
payload := term(),
status_code => integer(),
media_type => content_type(),
cookies => broen_cookies(),
cookie_path => broen_string(),
headers => broen_object()}
| #{redirect := unicode:unicode_binary()}.
%% The format of a broen response that should be returned by the serializer plugin<br/>
%% <b>payload</b> - The payload of the response<br/>
%% <b>status_code</b> - Status code of the response<br/>
%% <b>media_type</b> - The MIME content type of the payload<br/>
%% <b>cookies</b> - Additional cookies to be sent to user<br/>
%% <b>cookie_path</b> -  The cookie path<br/>
%% <b>headers</b> - Additional headers for the HTTP response<br/>
%% Alternatively the response can also be a redirect.

-export_type([content_type/0, broen_request/0, broen_response/0]).


%% @doc Registers metrics with folsom
-spec register_metrics() -> ok.
register_metrics() ->
  Groups = application:get_env(broen, metric_groups, []),
  [begin
     Key = iolist_to_binary(["broen_core.query.", G]),
     KeyT = iolist_to_binary(["broen_core.query.", G, ".timeout"]),
     KeyL = iolist_to_binary(["broen_core.query.", G, ".latency"]),
     folsom_metrics:new_spiral(binary_to_atom(Key, utf8)),
     folsom_metrics:new_spiral(binary_to_atom(KeyT, utf8)),
     folsom_metrics:new_histogram(binary_to_atom(KeyL, utf8), slide_uniform)
   end || G <- Groups],

  [folsom_metrics:new_spiral(C)
   || C <- ['broen_core.success',
            'broen_core.query.unknown',
            'broen_core.query.unknown.timeout',
            'broen_core.failure.crash',
            'broen_core.failure.500',
            'broen_core.failure.503',
            'broen_core.failure.404']],
  [folsom_metrics:new_histogram(H, slide_uniform)
   || H <- ['broen_core.query.unknown.latency']],
  folsom_metrics:new_spiral('broen_auth.failure'),
  ok.

handle(Req0, Exchange, CookiePath, Options) ->
  try
    RoutingKey = routing_key(Req0, Options),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
    case broen_request:check_http_origin(Req0, RoutingKey) of
      {_, unknown_origin} ->
        folsom_metrics:notify({'broen_core.failure.403', 1}),
        cowboy_req:reply(403,
                         #{<<"content-type">> => <<"text/plain">>},
                         <<"Forbidden">>,
                         Req0);
      {Origin, OriginMode} ->
        {AmqpRes, ExtraCookies} = amqp_call(Req0, Exchange, RoutingKey, Timeout),
        ReqWithCookies = lists:foldl(fun set_extra_cookie/2, Req0, ExtraCookies),
        case AmqpRes of
          {ok, PackedResponse, ContentType} ->
            {ok, SerializerMod} = application:get_env(broen, serializer_mod),
            case SerializerMod:deserialize(PackedResponse, ContentType) of
              {ok, Response} ->
                folsom_metrics:notify({'broen_core.success', 1}),
                build_response(ReqWithCookies, Response, CookiePath, OriginMode, Origin);
              {error, invalid_content_type} ->
                folsom_metrics:notify({'broen_core.failure.500', 1}),
                cowboy_req:reply(500,
                                 #{<<"content-type">> => <<"text/plain">>},
                                 iolist_to_binary([io_lib:format("Got wrong type of Media Type in response: ~ts",
                                                                 [ContentType])]),
                                 ReqWithCookies)
            end;
          {error, timeout} ->
            {_, MetricTimeout, _} = subsystem_metric(RoutingKey),
            folsom_metrics:notify({MetricTimeout, 1}),
            cowboy_req:reply(504,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"API Broen timeout">>,
                             ReqWithCookies);
          {error, {reply_code, 312}} ->
            folsom_metrics:notify({'broen_core.failure.404', 1}),
            cowboy_req:reply(404,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"Not found">>,
                             ReqWithCookies);
          {error, no_route} ->
            folsom_metrics:notify({'broen_core.failure.503', 1}),
            cowboy_req:reply(503,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"Service unavailable (no_route)">>,
                             ReqWithCookies);
          {error, csrf_verification_failed} ->
            cowboy_req:reply(403,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"Forbidden">>,
                             ReqWithCookies);
          {error, Reason} ->
            folsom_metrics:notify({'broen_core.failure.500', 1}),
            cowboy_req:reply(500,
                             #{<<"content-type">> => <<"text/plain">>},
                             iolist_to_binary([io_lib:format("~p~n", [Reason])]),
                             ReqWithCookies)
        end
    end
  catch
    _: request_error ->
      ok = lager:warning("Bad request: ~p Error: ~p StackTrace: ~p", [Req0, erlang:get_stacktrace()]),
      cowboy_req:reply(400,
                       #{<<"content-type">> => <<"text/plain">>},
                       <<"Bad request">>,
                       Req0);

    _: Error ->
      Now = erlang:timestamp(),
      Token = base64:encode(crypto:hash(sha256, term_to_binary(Now))),
      ok = lager:error("Crash: ~p Error: ~p Request ~p StackTrace: ~p", [Token, Error, Req0, erlang:get_stacktrace()]),
      folsom_metrics:notify({'broen_core.failure.crash', 1}),
      cowboy_req:reply(500,
                       #{<<"content-type">> => <<"text/plain">>},
                       iolist_to_binary([io_lib:format("Internal error, broen code crashed ~p~n", [Token])]),
                       Req0)
  end.


%% Internal functions
%% ---------------------------------------------------------------------------------
set_extra_cookie({CookieName, CookieValue}, R) ->
  Value = maps:get(value, CookieValue),
  MaxAge = maps:get(max_age, CookieValue),
  Path = maps:get(path, CookieValue, <<"/">>),
  Domain = maps:get(domain, CookieValue),

  cowboy_req:set_resp_cookie(CookieName, Value, R, #{
    domain => Domain,
    path => Path,
    max_age => MaxAge
  }).

amqp_call(Req, Exchange, RoutingKey, Timeout) ->
  TimeZero = os:timestamp(),
  {ok, AuthMod} = application:get_env(broen, auth_mod),
  case AuthMod:authenticate(Req) of
    {error, csrf_verification_failed} -> {{error, csrf_verification_failed}, []};
    {error, {csrf_verification_failed, Cookies}} ->
      {{error, csrf_verification_failed}, Cookies};
    {error, _} ->
      {handle_http(TimeZero, [], Req, Exchange, RoutingKey, Timeout), []};
    {ok, AuthData, Cookies} ->
      {handle_http(TimeZero, AuthData, Req, Exchange, RoutingKey, Timeout), Cookies}
  end.

handle_http(TimeZero, AuthData, Arg, Exch, RoutingKey, Timeout) ->
  Request = broen_request:build_request(Arg, RoutingKey, AuthData),
  {Metric, _, MetricL} = subsystem_metric(RoutingKey),
  folsom_metrics:notify({Metric, 1}),
  TimeBefore = os:timestamp(),
  {ok, SerializerMod} = application:get_env(broen, serializer_mod),
  {Packed, ContentType} = SerializerMod:serialize(Request),
  Reply = ad_client:call_timeout(amqp_rpc,
                                 Exch,
                                 RoutingKey,
                                 Packed,
                                 ContentType,
                                 [{timeout, timer:seconds(Timeout)}]),
  TimeAfter = os:timestamp(),
  histogram_notify(MetricL, timer:now_diff(TimeAfter, TimeZero) div 1000),
  lager:debug("broen_core:amqp_call ~p ~p", [timer:now_diff(TimeBefore, TimeZero), timer:now_diff(TimeAfter, TimeZero)]),
  case Reply of
    {error, timeout} ->
      lager:warning("broen_core:amqp_call timeout ~s ~p", [RoutingKey, Request]);
    _ -> ok
  end,
  Reply.

routing_key(Req, Options) ->
  Path = cowboy_req:path_info(Req),
  TrailingSlash = binary:last(cowboy_req:path(Req)) == $/,

  case valid_route(Path) of
    false -> <<"route.invalid">>;
    true when TrailingSlash ->
      route(proplists:get_bool(keep_dots_in_routing_keys, Options), Path ++ [<<>>]);
    true ->
      route(proplists:get_bool(keep_dots_in_routing_keys, Options), Path)
  end.

valid_route(Paths) ->
  Sum = lists:foldl(fun(El, Sum) -> Sum + byte_size(El) end, 0, Paths),
  Sum =< 255.

%% '.' is converted to '_' iff the keep_dots_in_routing_key is false,
%% otherwise it is left as a '.'
route(false, Route) ->
  Mapped = lists:map(fun(El) -> binary:replace(El, <<".">>, <<"_">>, [global]) end, Route),
  route(true, Mapped);
route(true, [First | Rest]) ->
  lists:foldl(fun(El, SoFar) -> <<SoFar/binary, ".", El/binary>> end, First, Rest).


%% Decoders of various responses
%% ---------------------------------------------------------------------------------
build_response(Req, #{redirect := URL}, _, _, _) ->
  cowboy_req:reply(
    302,
    #{<<"location">> => URL},
    <<>>,
    Req
  );
build_response(Req, Response, CookiePath, OriginMode, Origin) ->
  StatusCode = maps:get(status_code, Response, 200),
  Content = maps:get(payload, Response, <<>>),
  MediaType = maps:get(media_type, Response, <<>>),
  RespwithCookies = cookies(Req, Response, CookiePath),
  cowboy_req:reply(
    StatusCode,
    maps:from_list(headers(Response, OriginMode, Origin) ++ [{<<"content-type">>, MediaType}]),
    Content,
    RespwithCookies
  ).

headers(Response, OriginMode, Origin) ->
  Headers = maps:to_list(maps:get(headers, Response, #{})),
  [{binary_to_list(N), binary_to_list(V)} || {N, V} <- append_cors(Headers, Origin, OriginMode)].

append_cors(Headers, _, same_origin) -> Headers;
append_cors(Headers, Origin, allow_origin) ->
  case lists:keysearch(?ACAO_HEADER, 1, Headers) of
    false -> [{?ACAO_HEADER, Origin} | Headers];
    _ -> Headers
  end.

cookies(InitialReq, Response, DefaultCookiePath) ->
  Cookies = maps:to_list(maps:get(cookies, Response, #{})),
  CookiePath = maps:get(cookie_path, Response, DefaultCookiePath),
  DefaultExpires = iso8601:format({{2038, 1, 17}, {12, 34, 56}}),
  lists:foldl(fun(Cookie, Req) -> set_cookie(Cookie, CookiePath, DefaultExpires, Req) end, InitialReq, Cookies).

set_cookie({CookieName, CookieValue}, DefaultCookiePath, DefaultExpires, Req) ->
  Expiry = parse_expiry(maps:get(expires, CookieValue, DefaultExpires)),
  CookiePath = maps:get(path, CookieValue, DefaultCookiePath),
  Domain = maps:get(domain, CookieValue, undefined),
  Secure = maps:get(secure, CookieValue, false),
  HttpOnly = maps:get(http_only, CookieValue, false),
  Value = maps:get(value, CookieValue),
  cowboy_req:set_resp_cookie(CookieName, Value,
                             Req,
                             #{
                               domain => Domain,
                               path => CookiePath,
                               secure => Secure,
                               http_only => HttpOnly,
                               max_age => Expiry
                             }).

parse_expiry(Date) ->
  ParsedDate = parse_date(Date),
  UTC = calendar:universal_time(),
  Secs = calendar:datetime_to_gregorian_seconds(UTC),
  Expires = calendar:datetime_to_gregorian_seconds(ParsedDate),
  if
    Expires - Secs > 0 -> Expires - Secs;
    true -> 0
  end.


parse_date(Date) when is_list(Date) ->
  parse_date(list_to_binary(Date));
parse_date(Date) ->
  try
    iso8601:parse(Date)
  catch
    _:badarg ->
      cow_date:parse_date(Date)
  end.

%% Other
%% ---------------------------------------------------------------------------------
subsystem_metric(RK) when is_binary(RK) ->
  case binary:split(RK, <<".">>) of
    [SS | _] ->
      Key = iolist_to_binary(["broen_core.query.", SS]),
      KeyT = iolist_to_binary(["broen_core.query.", SS, ".timeout"]),
      KeyL = iolist_to_binary(["broen_core.query.", SS, ".latency"]),
      try
        {binary_to_existing_atom(Key, utf8), binary_to_existing_atom(KeyT, utf8), binary_to_existing_atom(KeyL, utf8)}
      catch
        error:badarg ->
          lager:info("subsystem_metric unkown rk ~p ~p ~p", [Key, KeyT, KeyL]),
          {'broen_core.query.unknown',
           'broen_core.query.unknown.timeout',
           'broen_core.query.unknown.latency'}
      end;
    _ ->
      {'broen_core.query.unknown',
       'broen_core.query.unknown.timeout',
       'broen_core.query.unknown.latency'}
  end.

histogram_notify(Name, Diff) ->
  case folsom_metrics:notify(Name, Diff) of
    {error, Name, nonexistent_metric} ->
      folsom_metrics:new_histogram(Name, slide_uniform),
      folsom_metrics:notify(Name, Diff);
    Res ->
      Res
  end.


month_str_to_int("Jan") -> 1;
month_str_to_int("Feb") -> 2;
month_str_to_int("Mar") -> 3;
month_str_to_int("Apr") -> 4;
month_str_to_int("May") -> 5;
month_str_to_int("Jun") -> 6;
month_str_to_int("Jul") -> 7;
month_str_to_int("Aug") -> 8;
month_str_to_int("Sep") -> 9;
month_str_to_int("Oct") -> 10;
month_str_to_int("Nov") -> 11;
month_str_to_int("Dec") -> 12.


stringdate_to_datetime([$ |T]) ->
  stringdate_to_datetime(T);
stringdate_to_datetime([_D1, _D2, _D3, $\,, $ |Tail]) ->
  stringdate_to_datetime1(Tail).

stringdate_to_datetime1([A, B, $\s |T]) ->
  stringdate_to_datetime2(T, erlang:list_to_integer([A,B]));
stringdate_to_datetime1([A, $\s |T]) ->
  stringdate_to_datetime2(T, erlang:list_to_integer([A])).

stringdate_to_datetime2([M1, M2, M3, $\s , Y1, Y2, Y3, Y4, $\s,
                         H1, H2, $:, Min1, Min2,$:,
                         S1, S2,$\s ,$G, $M, $T|_], Day) ->
  {{erlang:list_to_integer([Y1,Y2,Y3,Y4]),
    month_str_to_int([M1, M2, M3]), Day},
   {erlang:list_to_integer([H1, H2]),
    erlang:list_to_integer([Min1, Min2]),
    erlang:list_to_integer([S1, S2])}}.