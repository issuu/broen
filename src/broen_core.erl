%%% ---------------------------------------------------------------------------------
%%% @doc
%%% broen_core turns HTTP requests/responses into AMQP RPC messaging.
%%% Given a HTTP Request, this module will first authenticate it using the provided
%%% authentication plugin and the publish the message serialized with the serializer
%%% plug over AMQP. Upon receiving a response, the module will respond back over HTTP.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_core).

-include_lib("yaws/include/yaws_api.hrl").

-export([handle/4,
         handle_cowboy/4]).
-export([register_metrics/0]).

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
protocol := http | https,
cookies := broen_object(),
http_headers := broen_object(),
request := broen_string(),
method := broen_string(),
client_data := broen_nullable_string(),
fullpath := broen_string(),
appmoddata := broen_string(),
referer := broen_nullable_string(),
useragent := broen_string(),
client_ip := broen_string(),
routing_key := broen_string(),
queryobj := broen_object(),
auth_data := term(),
querydata => broen_string(),
postobj => broen_object(),
multipartobj => term()}.
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

handle_cowboy(Req0, Exchange, CookiePath, Options) ->
  RoutingKey = routing_key_cowboy(cowboy_req:path_info(Req0), Options),
  Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
  case broen_request:check_http_origin_cowboy(Req0, RoutingKey) of
    {_, unknown_origin} ->
      folsom_metrics:notify({'broen_core.failure.403', 1}),
      cowboy_req:reply(403,
                       #{<<"content-type">> => <<"text/plain">>},
                       <<"Forbidden">>,
                       Req0);
    {Origin, OriginMode} ->
      {AmqpRes, ExtraCookies} = amqp_call_cowboy(Req0, Exchange, RoutingKey, Timeout),
      ReqWithCookies = lists:foldl(fun({Name, Value}, R) -> cowboy_req:set_resp_cookie(Name, Value, R) end,
                                   Req0, ExtraCookies),
      case AmqpRes of
        {ok, PackedResponse, ContentType} ->
          {ok, SerializerMod} = application:get_env(broen, serializer_mod),
          case SerializerMod:deserialize(PackedResponse, ContentType) of
            {ok, Response} ->
              folsom_metrics:notify({'broen_core.success', 1}),
              build_response_cowboy(ReqWithCookies, Response, CookiePath, OriginMode, Origin);
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
  end.


%% @doc Main handler processing thin layer requests and replying back
handle(#arg{clidata    = {partial, CliData},
            appmoddata = AppModData,
            cont       = undefined}, _Exch, _CookiePath, _Options) ->
  lager:warning("Partial request ~p of size ~p - Trying to get more ", [AppModData, byte_size(CliData)]),
  {get_more, {cont, size(CliData)}, CliData};
handle(#arg{clidata    = {partial, CliData},
            appmoddata = AppModData,
            state      = State,
            cont       = Cont}, _Exch, _CookiePath, _Options) ->
  {cont, Sz0} = Cont,
  Sz1 = Sz0 + size(CliData),
  lager:warning("Continued partial request ~p of size ~p - Trying to get more ", [AppModData, byte_size(CliData)]),
  {get_more, {cont, Sz1}, <<State/binary, CliData/binary>>};
handle(#arg{clidata    = CliData,
            appmoddata = AppModData,
            req        = #http_request{method = M}}, _Exch, _CookiePath, _Options)
  when M == 'POST' orelse M == 'PUT',
       byte_size(CliData) > ?CLIENT_REQUEST_BODY_LIMIT ->
  lager:warning("Reject request ~p - size too large: ~p", [AppModData, byte_size(CliData)]),
  [{status, 413},
   {content, "text/plain", "Request size too large"}];
handle(Arg, Exch, CookiePath, Options) ->
  RoutingKey = routing_key(Arg#arg.appmoddata, Options),
  Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),

  case broen_request:check_http_origin(Arg, RoutingKey) of
    {_, unknown_origin} ->
      folsom_metrics:notify({'broen_core.failure.403', 1}),
      [{status, 403},
       {content, "text/plain", "Forbidden"}];
    {Origin, OriginMode} ->
      {AmqpRes, ExtraCookies} = amqp_call(Arg, Exch, RoutingKey, Timeout),
      Res = case AmqpRes of
              {ok, PackedResponse, ContentType} ->
                {ok, SerializerMod} = application:get_env(broen, serializer_mod),
                case SerializerMod:deserialize(PackedResponse, ContentType) of
                  {ok, Response} ->
                    folsom_metrics:notify({'broen_core.success', 1}),
                    build_response(Response, Response, CookiePath, OriginMode, Origin);
                  {error, invalid_content_type} ->
                    folsom_metrics:notify({'broen_core.failure.500', 1}),
                    [{status, 500},
                     {content, "text/plain",
                      io_lib:format("Got wrong type of Media Type in response: ~ts", [ContentType])}]
                end;
              {error, timeout} ->
                {_, MetricTimeout, _} = subsystem_metric(RoutingKey),
                folsom_metrics:notify({MetricTimeout, 1}),
                [{status, 504},
                 {content, "text/plain", "API Broen timeout"}];
              {error, {reply_code, 312}} ->
                folsom_metrics:notify({'broen_core.failure.404', 1}),
                [{status, 404},
                 {content, "text/plain", "Not found."}];
              {error, no_route} ->
                folsom_metrics:notify({'broen_core.failure.503', 1}),
                [{status, 503},
                 {content, "text/plain", io_lib:format("Service unavailable (~p)~n", [no_route])}];
              {error, csrf_verification_failed} ->
                [{status, 403},
                 {content, "text/plain", "Forbidden"}];
              {error, Reason} ->
                folsom_metrics:notify({'broen_core.failure.500', 1}),
                [{status, 500},
                 {content, "text/plain", io_lib:format("~p~n", [Reason])}]
            end,
      Res ++ ExtraCookies
  end.


%% Internal functions
%% ---------------------------------------------------------------------------------
amqp_call_cowboy(Req, Exchange, RoutingKey, Timeout) ->
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

amqp_call(Arg, Exch, RoutingKey, Timeout) ->
  TimeZero = os:timestamp(),
  {ok, AuthMod} = application:get_env(broen, auth_mod),
  case AuthMod:authenticate(Arg) of
    {error, csrf_verification_failed} -> {{error, csrf_verification_failed}, []};
    {error, {csrf_verification_failed, Cookies}} ->
      {{error, csrf_verification_failed}, [{header, C} || C <- Cookies]};
    {error, _} ->
      {handle_http(TimeZero, [], Arg, Exch, RoutingKey, Timeout), []};
    {ok, AuthData, Cookies} ->
      {handle_http(TimeZero, AuthData, Arg, Exch, RoutingKey, Timeout), [{header, C} || C <- Cookies]}
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

%% @todo consider hardening this a bit and set up a ruleset.
%% @todo especially protection against malicious use must be handled here.
routing_key_cowboy(Path, Options) ->
  case valid_route_cowboy(Path) of
    false -> <<"route.invalid">>;
    true -> route_cowboy(proplists:get_bool(keep_dots_in_routing_keys, Options), Path)
  end.

routing_key(Path, Options) ->
  list_to_binary(
    case valid_route(Path) of
      valid -> route(proplists:get_bool(keep_dots_in_routing_keys, Options), Path);
      invalid -> "route.invalid"
    end).

valid_route_cowboy(Paths) ->
  Sum = lists:foldl(fun(El, Sum) -> Sum + byte_size(El) end, 0, Paths),
  Sum =< 255.

%% a path is valid if its length is <= 1024 chars
valid_route(Path) when is_binary(Path) and byte_size(Path) > 255 -> invalid;
valid_route(Path) when is_list(Path) and length(Path) > 1024     -> invalid;
valid_route(_Path)                                               -> valid.

%% '.' is converted to '_' iff the keep_dots_in_routing_key is false,
%% otherwise it is left as a '.'
route_cowboy(false, Route) ->
  Mapped = lists:map(fun(El) -> binary:replace(El, <<".">>, <<"_">>, [global]) end, Route),
  route_cowboy(true, Mapped);
route_cowboy(true, [First | Rest]) ->
  lists:foldl(fun(El, SoFar) -> <<SoFar/binary, ".", El/binary>> end, First, Rest).

route(Dots, [$/ | Str])  -> [$. | route(Dots, Str)];
route(false, [$. | Str]) -> [$_ | route(false, Str)];
route(Dots, [X | Str])   -> [X | route(Dots, Str)];
route(_, [])             -> [].

%% Decoders of various responses
%% ---------------------------------------------------------------------------------
build_response(#{redirect := URL}, _, _, _, _) ->
  [{redirect, binary_to_list(URL)}];
build_response(Response, Response, CookiePath, OriginMode, Origin) ->
  content(Response, CookiePath, OriginMode, Origin) ++ status_code(Response).


build_response_cowboy(Req, #{redirect := URL}, _, _, _) ->
  cowboy_req:reply(
    302,
    [{<<"location">>, URL}],
    <<>>,
    Req
  );
build_response_cowboy(Req, Response, CookiePath, OriginMode, Origin) ->
  StatusCode = maps:get(status_code, Response, 200),
  Content = maps:get(payload, Response, <<>>),
  MediaType = maps:get(media_type, Response, <<>>),
  RespwithCookies = cookies_cowboy(Req, Response, CookiePath),
  cowboy_req:reply(
    StatusCode,
    maps:from_list(headers_cowboy(Response, OriginMode, Origin) ++ [{<<"content-type">>, MediaType}]),
    Content,
    RespwithCookies
  ).

status_code(Response) ->
  case maps:find(status_code, Response) of
    error -> [];
    {ok, Code} when is_integer(Code) -> [{status, Code}]
  end.

content(Response, DefaultCookiePath, OriginMode, Origin) ->
  Headers = headers(Response, DefaultCookiePath, OriginMode, Origin),
  case maps:find(payload, Response) of
    error -> Headers;
    {ok, Payload} ->
      MediaType = maps:get(media_type, Response, undefined),
      [{content, format_media_type(MediaType), Payload}] ++ Headers
  end.

headers_cowboy(Response, OriginMode, Origin) ->
  Headers = maps:to_list(maps:get(headers, Response, #{})),
  [{binary_to_list(N), binary_to_list(V)} || {N, V} <- append_cors(Headers, Origin, OriginMode)].

headers(Response, DefaultCookiePath, OriginMode, Origin) ->
  Cookies = maps:to_list(maps:get(cookies, Response, #{})),
  CookiePath = maps:get(cookie_path, Response, DefaultCookiePath),
  Headers = maps:to_list(maps:get(headers, Response, #{})),
  DefaultExpires = iso8601:format({{2038, 1, 17}, {12, 34, 56}}),
  [format_cookie(N, V, DefaultExpires, CookiePath) || {N, V} <- Cookies] ++
    [{header, {binary_to_list(N), binary_to_list(V)}} || {N, V} <- append_cors(Headers, Origin, OriginMode)].

append_cors(Headers, _, same_origin) -> Headers;
append_cors(Headers, Origin, allow_origin) ->
  case lists:keysearch(?ACAO_HEADER, 1, Headers) of
    false -> [{?ACAO_HEADER, list_to_binary(Origin)} | Headers];
    _ -> Headers
  end.

cookies_cowboy(InitialReq, Response, DefaultCookiePath) ->
  Cookies = maps:to_list(maps:get(cookies, Response, #{})),
  CookiePath = maps:get(cookie_path, Response, DefaultCookiePath),
  DefaultExpires = iso8601:format({{2038, 1, 17}, {12, 34, 56}}),
  lists:foldl(fun(Cookie, Req) -> set_cookie(Cookie, CookiePath, DefaultExpires, Req)
              end, InitialReq, Cookies).

set_cookie({CookieName, CookieValue}, DefaultCookiePath, DefaultExpires, Req) ->
  Expiry = parse_expiry(maps:get(expires, CookieValue, DefaultExpires)),
  CookiePath = maps:get(path, CookieValue, DefaultCookiePath),
  Domain = maps:get(domain, CookieValue, undefined),
  Secure = maps:get(secure, CookieValue, false),
  HttpOnly = maps:get(http_only, CookieValue, false),
  Value = maps:get(value, CookieValue),
  cowboy_req:set_resp_cookie(CookieName, cow_qs:urlencode(Value),
                             Req,
                             #{
                               domain => Domain,
                               path => CookiePath,
                               secure => Secure,
                               http_only => HttpOnly,
                               max_age => Expiry
                             }).

format_cookie(N, CookieValue, DefaultExpires, DefaultCookiePath) ->
  Expiry = {expires, parse_date(maps:get(expires, CookieValue, DefaultExpires))},
  CookiePath = {path, case maps:get(path, CookieValue, DefaultCookiePath) of
    B when is_binary(B) -> binary_to_list(B);
    L -> L

  end},
  Domain = case maps:get(domain, CookieValue, undefined) of
             undefined -> [];
             D -> [{domain, binary_to_list(D)}]
           end,

  Secure = case maps:get(secure, CookieValue, false) of
             true -> [secure];
             false -> []
           end,
  HttpOnly = case maps:get(http_only, CookieValue, false) of
               true -> [http_only];
               false -> []
             end,
  Options = [Expiry, CookiePath] ++ Domain ++ Secure ++ HttpOnly,
  lager:warning("Options ~p", [Options]),
  yaws_api:set_cookie(binary_to_list(N), binary_to_list(maps:get(value, CookieValue)), Options).

parse_expiry(Date) ->
  ParsedDate = parse_date(Date),
  UTC = calendar:universal_time(),
  Secs = calendar:datetime_to_gregorian_seconds(UTC),
  Expires = calendar:datetime_to_gregorian_seconds(ParsedDate),
  if
    Expires - Secs > 0 -> Expires - Secs;
    true -> 0
  end.


parse_date(Date) when is_binary(Date) ->
  parse_date(binary_to_list(Date));
parse_date(Date) ->
  try
    iso8601:parse(Date)
  catch
    _:badarg ->
      yaws:stringdate_to_datetime(Date)
  end.


format_media_type(undefined)           -> "text/plain";
format_media_type(B) when is_binary(B) -> binary_to_list(B);
format_media_type(L) when is_list(L)   -> L.

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
