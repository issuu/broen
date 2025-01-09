%%% ---------------------------------------------------------------------------------
%%% @doc
%%% broen_core turns HTTP requests/responses into AMQP RPC messaging.
%%% Given a HTTP Request, this module will first authenticate it using the provided
%%% authentication plugin and the publish the message serialized with the serializer
%%% plug over AMQP. Upon receiving a response, the module will respond back over HTTP.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_core).


-export([handle/3]).
-export([register_metrics/0]).
-define(CLIENT_REQUEST_BODY_LIMIT, 65536).
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
  lager:info("Register folsom metrics with query paths: ~s", [Groups]),
  [begin
     Key = iolist_to_binary(["broen_core.query.", G]),
     KeyA = iolist_to_binary(["broen_core.query.", G, ".gone"]),
     KeyT = iolist_to_binary(["broen_core.query.", G, ".timeout"]),
     KeyL = iolist_to_binary(["broen_core.query.", G, ".latency"]),
     folsom_metrics:new_spiral(binary_to_atom(Key, utf8)),
     folsom_metrics:new_spiral(binary_to_atom(KeyA, utf8)),
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
            'broen_core.failure.404',
            'broen_auth.failure']],
  [folsom_metrics:new_histogram(H, slide_uniform)
   || H <- ['broen_core.query.unknown.latency']],

  register_prometheus_metrics(),
  ok.

register_prometheus_metrics() ->
  case application:get_env(broen, prometheus) of
    {ok, #{ prefix := Prefix }} ->
        register_prometheus_metrics(Prefix);
    undefined ->
        ok
  end.

register_prometheus_metrics(Prefix) ->
  lager:info("Register prometheus metrics using prefix: ~s", [Prefix]),
  S = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_success_total"]),utf8),
  prometheus_counter:declare([{name, S}, {help, "Count success requests."}]),
  prometheus_counter:inc(S, 0),

  F = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_failure_total"]),utf8),
  prometheus_counter:declare([{name, F}, {labels, [failure_type]}, {help, "Count failure requests."}]),
  [prometheus_counter:inc(F, [FailureType], 0) || FailureType <- ['400','403','404','413','415','500','502','503','504',crash,csrf]],

  QH = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query"]),utf8),
  prometheus_histogram:declare([
    {name, QH},
    {labels, [route]},
    %% Note that there is an extra implicit bucket from 60 sec to infinity.
    {buckets, [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000]},
    {help, "Query request time in milliseconds."}
  ]),
  Q = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query_total"]),utf8),
  prometheus_counter:declare([{name, Q}, {labels, [route]}, {help, "Count query route requests."}]),
  QG = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query_gone_total"]),utf8),
  prometheus_counter:declare([{name, QG}, {labels, [route]}, {help, "Count query route gone requests."}]),
  QT = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query_timeout_total"]),utf8),
  prometheus_counter:declare([{name, QT}, {labels, [route]}, {help, "Count query route timeout requests."}]),

  %% reset the unknown counter(s) on each startup
  [prometheus_counter:inc(M, [EndPoint], 0) || M <- [Q, QG, QT], EndPoint <- ['unknown']],

  %% This metric is exposed and used by whatever authentication module that using "broen" library.
  AF = binary_to_atom(iolist_to_binary([Prefix, "_broen_auth_failure_total"]),utf8),
  prometheus_counter:declare([{name, AF}, {labels, [failure_type]}, {help, "Count auth failure requests."}]),
  [prometheus_counter:inc(AF, [FailureType], 0) || FailureType <- ['400','403','404','413','415','500','502','503','504',crash,csrf]],

  ok.

prometheus_inc_counter(Suffix, Inc) ->
  prometheus_inc_counter(Suffix, [], Inc).
prometheus_inc_counter(Suffix, Labels, Inc) ->
  case application:get_env(broen, prometheus) of
    {ok, #{ prefix := Prefix }} ->
        MetricName = binary_to_atom(iolist_to_binary([Prefix, "_", atom_to_list(Suffix), "_total"]),utf8),
        %%lager:debug("increasing prometheus metric counter ~p, labels ~p with ~p", [MetricName, Labels, Inc]),
        prometheus_counter:inc(MetricName, Labels, Inc);
    undefined ->
        ok
  end.

handle(
  Req0,
  #{
    serializer_mod := SerializerMod,
    keep_dots_in_routing_keys := KeepDotsRK
  } = Conf,
  CookiePath) ->
  try
    RoutingKey = routing_key(Req0, KeepDotsRK),
    case broen_request:check_http_origin(Req0, RoutingKey) of
      {_, unknown_origin} ->
        folsom_metrics:notify({'broen_core.failure.403', 1}),
        prometheus_inc_counter('broen_core_failure', ['403'], 1),
        cowboy_req:reply(403,
                         #{<<"content-type">> => <<"text/plain">>},
                         <<"Forbidden">>,
                         Req0);
      {Origin, OriginMode} ->
        {AmqpRes, ExtraCookies} = amqp_call(Req0, RoutingKey, Conf),
        ReqWithCookies = lists:foldl(fun(Cookie, Req) -> set_cookie(Cookie, <<"/">>, 0, Req) end, Req0, ExtraCookies),
        case AmqpRes of
          {ok, PackedResponse, ContentType} ->
            case SerializerMod:deserialize(PackedResponse, ContentType) of
              {ok, Response} ->
                folsom_metrics:notify({'broen_core.success', 1}),
                prometheus_inc_counter('broen_core_success', 1),
                build_response(ReqWithCookies, Response, CookiePath, OriginMode, Origin);
              {error, invalid_content_type} ->
                folsom_metrics:notify({'broen_core.failure.500', 1}),
                %% 415 Unsupported Media Type - seems more correct meassure
                prometheus_inc_counter('broen_core_failure', ['415'], 1),
                cowboy_req:reply(500,
                                 #{<<"content-type">> => <<"text/plain">>},
                                 iolist_to_binary([io_lib:format("Got wrong type of Media Type in response: ~ts",
                                                                 [ContentType])]),
                                 ReqWithCookies)
            end;
          {error, timeout} ->
            %% 504 Gateway Timeout
            prometheus_inc_counter('broen_core_failure', ['504'], 1),
            cowboy_req:reply(504,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"API Broen timeout">>,
                             ReqWithCookies);
          {error, {reply_code, 312}} ->
            folsom_metrics:notify({'broen_core.failure.404', 1}),
            prometheus_inc_counter('broen_core_failure', ['404'], 1),
            cowboy_req:reply(404,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"Not found">>,
                             ReqWithCookies);
          {error, no_route} ->
            %% 503 Service Unavailable
            folsom_metrics:notify({'broen_core.failure.503', 1}),
            prometheus_inc_counter('broen_core_failure', ['503'], 1),
            cowboy_req:reply(503,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"Service unavailable (no_route)">>,
                             ReqWithCookies);
          {error, csrf_verification_failed} ->
            prometheus_inc_counter('broen_core_failure', ['csrf'], 1),
            cowboy_req:reply(403,
                             #{<<"content-type">> => <<"text/plain">>},
                             <<"Forbidden">>,
                             ReqWithCookies);
          {error, Reason} ->
            %% 500 Internal Server Error
            folsom_metrics:notify({'broen_core.failure.500', 1}),
            prometheus_inc_counter('broen_core_failure', ['500'], 1),
            cowboy_req:reply(500,
                             #{<<"content-type">> => <<"text/plain">>},
                             iolist_to_binary([io_lib:format("~p~n", [Reason])]),
                             ReqWithCookies)
        end
    end
  catch
    throw: body_too_large ->
      %% 413 Payload Too Large
      prometheus_inc_counter('broen_core_failure', ['413'], 1),
      cowboy_req:reply(400,
                       #{<<"content-type">> => <<"text/plain">>},
                       <<"Body too large">>,
                       Req0);

    _: {request_error, _, _} = Error: StackTrace ->
      prometheus_inc_counter('broen_core_failure', ['400'], 1),
      lager:warning("Bad request: ~p Error: ~p StackTrace: ~p", [Req0, Error, StackTrace]),
      cowboy_req:reply(400,
                       #{<<"content-type">> => <<"text/plain">>},
                       <<"Bad request">>,
                       Req0);

    _: Error: StackTrace ->
      Now = erlang:timestamp(),
      Token = base64:encode(crypto:hash(sha256, term_to_binary(Now))),
      lager:error("Crash: ~p Error: ~p Request ~p StackTrace: ~p", [Token, Error, Req0, StackTrace]),
      folsom_metrics:notify({'broen_core.failure.crash', 1}),
      prometheus_inc_counter('broen_core_failure', ['crash'], 1),
      cowboy_req:reply(500,
                       #{<<"content-type">> => <<"text/plain">>},
                       iolist_to_binary([io_lib:format("Internal error ~p~n", [Token])]),
                       Req0)
  end.


%% Internal functions
%% ---------------------------------------------------------------------------------
amqp_call(_Req, invalid_route, _Conf) ->
  {{error, no_route}, []};
amqp_call(Req, RoutingKey, #{
  exchange := Exchange,
  serializer_mod := SerializerMod,
  auth_mod := AuthMod,
  partial_post_size := PartialPostSize,
  timeout := Timeout
}) ->
  TimeZero = os:timestamp(),
  case AuthMod:authenticate(Req) of
    {error, csrf_verification_failed} -> {{error, csrf_verification_failed}, []};
    {error, {csrf_verification_failed, Cookies}} ->
      {{error, csrf_verification_failed}, Cookies};
    {error, _} ->
      {handle_http(SerializerMod, PartialPostSize, TimeZero, [], Req, Exchange, RoutingKey, Timeout), []};
    {ok, AuthData, Cookies} ->
      {handle_http(SerializerMod, PartialPostSize, TimeZero, AuthData, Req, Exchange, RoutingKey, Timeout), Cookies}
  end.

handle_http(SerializerMod, PartialPostSize, TimeZero, AuthData, Arg, Exch, RoutingKey, Timeout) ->
  Request = broen_request:build_request(Arg, PartialPostSize, RoutingKey, AuthData),
  MetricGroup = metric_group_from_routing_key(RoutingKey),
  GroupCalledNotified = notify_group_called(MetricGroup),
  {Packed, ContentType} = SerializerMod:serialize(Request),
  Reply = ad_client:call_timeout(amqp_rpc,
                                 Exch,
                                 RoutingKey,
                                 Packed,
                                 ContentType,
                                 [{timeout, Timeout}]),
  TimeAfter = os:timestamp(),

  maybe_register_group(Reply, MetricGroup),
  case GroupCalledNotified of
    true -> ok;
    %% if we did not notify before,
    %% perhaps we now registered the metric,
    %% so try again
    false -> notify_group_called(MetricGroup)
  end,

  notify_group_latency(MetricGroup, TimeZero, TimeAfter),

  case Reply of
    {error, timeout} ->
      lager:warning("broen_core:amqp_call timeout ~s ~p", [RoutingKey, Request]),
      notify_group_timeout(MetricGroup);
    {error, no_route} ->
      notify_group_gone(MetricGroup);
    _ -> ok
  end,
  Reply.

routing_key(Req, KeepDotsRK) ->
  Path = cowboy_req:path_info(Req),
  TrailingSlash = binary:last(cowboy_req:path(Req)) == $/,

  case valid_route(Path) of
    false -> invalid_route;
    true when TrailingSlash ->
      route(KeepDotsRK, Path ++ [<<>>]);
    true ->
      route(KeepDotsRK, Path)
  end.

valid_route([]) ->
  false;
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

parse_expiry(Date) when is_integer(Date) -> Date;
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
metric_groups() -> application:get_env(broen, metric_groups, []).
metric_group_exists(MetricGroup) -> lists:any(fun (Item) -> Item == MetricGroup end, metric_groups()).

metric_group_key_count(MetricGroup) -> binary_to_atom(iolist_to_binary(["broen_core.query.", MetricGroup]), utf8).
metric_group_key_gone(MetricGroup) -> binary_to_atom(iolist_to_binary(["broen_core.query.", MetricGroup, ".gone"]), utf8).
metric_group_key_timeout(MetricGroup) -> binary_to_atom(iolist_to_binary(["broen_core.query.", MetricGroup, ".timeout"]), utf8).
metric_group_key_latency(MetricGroup) -> binary_to_atom(iolist_to_binary(["broen_core.query.", MetricGroup, ".latency"]), utf8).

%% register metric group if we did not see it before -
%% but only if the reply is not "immediate delivery failed"
%% error, as this is most probably a 404 and we don't want
%% to register random metric groups.
maybe_register_group({error, {reply_code, 312}}, _) -> ok;
maybe_register_group({error, no_route}, _) -> ok;
maybe_register_group(_, MetricGroup) -> register_metric_group(MetricGroup).

register_metric_group(MetricGroup) ->
  case metric_group_exists(MetricGroup) of
    true -> ok;
    false ->
      lager:info("Register metric group: ~s", [MetricGroup]),
      Key = metric_group_key_count(MetricGroup),
      KeyA = metric_group_key_gone(MetricGroup),
      KeyT = metric_group_key_timeout(MetricGroup),
      KeyL = metric_group_key_latency(MetricGroup),
      folsom_metrics:new_spiral(Key),
      folsom_metrics:new_spiral(KeyA),
      folsom_metrics:new_spiral(KeyT),
      folsom_metrics:new_histogram(KeyL, slide_uniform),
      register_prometheus_metric_group(MetricGroup),
      application:set_env(broen, metric_groups, [MetricGroup | metric_groups()]),
      ok
  end.

register_prometheus_metric_group(MetricGroup) ->
  case application:get_env(broen, prometheus) of
    {ok, #{ prefix := Prefix }} ->
        register_prometheus_metric_group(Prefix, MetricGroup);
    undefined ->
        ok
  end.
register_prometheus_metric_group(Prefix, MetricGroup) ->
  %% reset counter
  lager:info("Register prometheus metric group: ~s", [MetricGroup]),
  Q = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query_total"]),utf8),
  QG = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query_gone_total"]),utf8),
  QT = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query_timeout_total"]),utf8),
  prometheus_counter:inc(Q, [binary_to_atom(MetricGroup,utf8)], 0),
  prometheus_counter:inc(QG, [binary_to_atom(MetricGroup,utf8)], 0),
  prometheus_counter:inc(QT, [binary_to_atom(MetricGroup,utf8)], 0).

-spec metric_group_from_routing_key(binary()) -> binary().
metric_group_from_routing_key(RK) when is_binary(RK) ->
  case binary:split(RK, <<".">>) of
    [SS | _] -> SS;
    _ -> <<"unknown">>
  end.

 -spec notify_group_called(binary()) -> boolean().
notify_group_called(MetricGroup) ->
  case metric_group_exists(MetricGroup) of
    true ->
        folsom_metrics:notify({metric_group_key_count(MetricGroup), 1}),
        prometheus_inc_counter('broen_core_query', [binary_to_atom(MetricGroup,utf8)], 1),
        true;
    false ->
        false
  end.

notify_group_gone(MetricGroup) ->
  case metric_group_exists(MetricGroup) of
    false -> ok;
    true ->
      % metric group exists, but message could not be delivered,
      % meaning that a subsystem is now gone
      lager:warning("broen_core metric_group_gone ~s", [MetricGroup]),
      folsom_metrics:notify({metric_group_key_gone(MetricGroup), 1}),
      prometheus_inc_counter('broen_core_query_gone', [binary_to_atom(MetricGroup,utf8)], 1)
  end.

notify_group_timeout(MetricGroup) ->
  case metric_group_exists(MetricGroup) of
    true ->
        folsom_metrics:notify({metric_group_key_timeout(MetricGroup), 1}),
        prometheus_inc_counter('broen_core_query_timeout', [binary_to_atom(MetricGroup,utf8)], 1);
    false -> ok
  end.

notify_group_latency(MetricGroup, TimeZero, TimeAfter) ->
  case metric_group_exists(MetricGroup) of
    true ->
        Ms = timer:now_diff(TimeAfter, TimeZero) div 1000,
        histogram_notify(metric_group_key_latency(MetricGroup), Ms),
        notify_prometheus_group_latency(MetricGroup, Ms);
    false -> ok
  end.

histogram_notify(Name, Diff) ->
  case folsom_metrics:notify(Name, Diff) of
    {error, Name, nonexistent_metric} ->
      folsom_metrics:new_histogram(Name, slide_uniform),
      folsom_metrics:notify(Name, Diff);
    Res ->
      Res
  end.

notify_prometheus_group_latency(MetricGroup, Ms) ->
  case application:get_env(broen, prometheus) of
    {ok, #{ prefix := Prefix }} ->
        QH = binary_to_atom(iolist_to_binary([Prefix, "_broen_core_query"]),utf8),
        %%lager:debug("observing prometheus metric ~p, labels [~p], ms: ~p", [QH, binary_to_atom(MetricGroup,utf8), Ms]),
        prometheus_histogram:observe(QH, [binary_to_atom(MetricGroup,utf8)], Ms);
    undefined ->
        ok
  end.
