%%% ---------------------------------------------------------------------------------
%%% @doc
%%% This module handles building broen requests out of Yaws data.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_request).

-include_lib("eunit/include/eunit.hrl").
-include_lib("yaws/include/yaws_api.hrl").

%% API
-export([build_request/3,
         check_http_origin/2,
         check_http_origin_cowboy/2]).

-define(XFF_HEADER, "X-Forwarded-For").
-define(XRI_HEADER, "X-Real-Ip").
-define(XUA_HEADER, "X-User-Agent").
-define(PROTOCOL_HEADER_NAME, "X-Forwarded-Proto").
-define(CORS_HEADER, "Origin").

-spec build_request(#arg{}, binary(), list(broen_core:broen_other_key())) -> broen_core:broen_request().
build_request(#arg{headers    = Headers,
                   querydata  = Query,
                   fullpath   = FullPath,
                   appmoddata = AppModData,
                   req        = Request} = Arg,
              RoutingKey,
              AuthData) ->
  merge_maps([
               querydata(Query),
               postobj(Arg),
               multipartobj(Arg),
               #{
                 protocol => get_protocol_header(Arg),
                 cookies => format_cookies(Arg#arg.headers),
                 http_headers => http_headers(Arg#arg.headers),
                 request => request_type(Request),
                 method => request_type(Request),
                 client_data => client_data(Arg#arg.clidata, Arg#arg.state), %% Size already validated
                 fullpath => list_to_binary(FullPath),
                 appmoddata => list_to_binary(AppModData),
                 referer => referer(Headers),
                 useragent => ua(user_agent(Arg)),
                 client_ip => iolist_to_binary(client_ip(Arg)),
                 routing_key => RoutingKey,
                 queryobj => format_object(yaws_api:parse_query(Arg)),
                 auth_data => AuthData
               }
             ]);
build_request(Req, RoutingKey, AuthData) ->
  {Body, ReadReq} = get_body(Req),
  merge_maps([
               querydata_cowboy(cowboy_req:qs(ReadReq)),
               postobj_cowboy(ReadReq, Body),
               body(ReadReq, Body),
               #{
                 protocol => case cowboy_req:header(<<"x-forwarded-proto">>, ReadReq) of
                   <<"https">> -> https;
                   _ -> http
                 end,
                 cookies => maps:from_list(cowboy_req:parse_cookies(ReadReq)),
                 http_headers => cowboy_req:headers(ReadReq),
                 request => cowboy_req:method(ReadReq),
                 method => cowboy_req:method(ReadReq),
                 fullpath => iolist_to_binary(cowboy_req:uri(ReadReq)),
                 appmoddata => cowboy_req:path(ReadReq),
                 referer => cowboy_req:header(<<"referer">>, ReadReq),
                 user_agent => cowboy_req:header(<<"user-agent">>, ReadReq),
                 client_ip => iolist_to_binary(client_ip_cowboy(ReadReq)),
                 routing_key => RoutingKey,
                 queryobj => maps:from_list(cowboy_req:parse_qs(Req)),
                 auth_data => AuthData}
             ]).

get_body(Req) ->
  case cowboy_req:header(<<"content-type">>, Req) of
    <<"multipart/form-data", _/binary>> ->
      B = get_body_multipart(Req, []),
      B;
    _ ->
      get_body(Req, <<>>)
  end.

get_body_multipart(Req0, Acc) ->
  case cowboy_req:read_part(Req0) of
    {ok, Headers, Req1} ->
      {ok, Body, Req} = stream_body(Req1, <<>>),
      get_body_multipart(Req, [{Headers, Body} | Acc]);
    {done, Req} ->
      {{[parse_part(P) || P <- lists:reverse(Acc)]}, Req}
  end.

parse_part({#{<<"content-disposition">> := <<"form-data; ", Rest/binary>>} = M, Body}) ->
  Parts = binary:split(Rest, <<";">>, [global]),
  Parsed = [begin
              Trimmed = trim_part(P),
              NoQuotes = binary:replace(Trimmed, <<"\"">>, <<>>, [global]),
              [K, V] = binary:split(NoQuotes, <<"=">>, [global]),
              {K, V}
            end || P <- Parts],
  {value, {_, Name}, OtherData} = lists:keytake(<<"name">>, 1, Parsed),

  {_, M2} = maps:take(<<"content-disposition">>, M),
  {Name, {[
            {<<"opts">>, {OtherData ++ maps:to_list(M2)}},
            {<<"body">>, Body}

          ]}}.


trim_part(<<" ", Rest/binary>>) -> trim_part(Rest);
trim_part(B)                    -> B.

stream_body(Req0, Acc) ->
  case cowboy_req:read_part_body(Req0) of
    {more, Data, Req} ->
      stream_body(Req, <<Acc/binary, Data/binary>>);
    {ok, Data, Req} ->
      {ok, <<Acc/binary, Data/binary>>, Req}
  end.

get_body(Req0, SoFar) ->
  case cowboy_req:read_body(Req0) of
    {ok, Data, Req} ->
      {<<SoFar/binary, Data/binary>>, Req};
    {more, Data, Req} ->
      get_body(Req, {<<SoFar/binary, Data/binary>>})
  end.

-spec check_http_origin(#arg{}, binary()) -> {string(), 'same_origin'|'allow_origin'|'unknown_origin'}.
check_http_origin(Arg = #arg{headers = Headers, req = Request}, RoutingKey) ->
  Method = request_type(Request),
  Origin = cors_header(Arg),
  Referer = referer(Headers),
  UserAgent = ua(user_agent(Arg)),
  {Origin, check_http_origin(Method, Origin, RoutingKey, UserAgent, Referer)}.

check_http_origin_cowboy(Req, RoutingKey) ->
  Method = cowboy_req:method(Req),
  Origin = cowboy_req:header(<<"origin">>, Req),
  Referer = cowboy_req:header(<<"referer">>, Req),
  UserAgent = cowboy_req:header(<<"user-agent">>, Req),
  {Origin, check_http_origin(Method, Origin, RoutingKey, UserAgent, Referer)}.

check_http_origin(_Method, undefined, _RoutingKey, _UserAgent, _Referer)     -> same_origin; % Not cross-origin request
check_http_origin(<<"GET">>, _Origin, _RoutingKey, _UserAgent, _Referer)     -> allow_origin; % Disregard GET method
check_http_origin(<<"OPTIONS">>, _Origin, _RoutingKey, _UserAgent, _Referer) -> allow_origin; % Disregard OPTIONS method
check_http_origin(Method, Origin, RoutingKey, UserAgent, Referer) ->
  OriginTokens = lists:reverse(parse_uri(Origin)),
  case match_origins(OriginTokens) of
    true ->
      allow_origin;
    false ->
      case match_white_listed_method(RoutingKey, Method) of
        [Method] ->
          allow_origin;
        _ ->
          lager:warning("method: ~s, routing-key: ~s, origin: ~s, user-agent: ~s, referer: ~s",
                        [Method, RoutingKey, Origin, UserAgent, Referer]),
          unknown_origin
      end
  end.

parse_uri(Origin) when is_binary(Origin) ->
  case http_uri:parse(Origin) of
    {ok, Res} -> binary:split(element(3, Res), <<".">>, [global]);
    _ -> binary:split(Origin, [<<":">>, <<".">>], [global])
  end;
parse_uri(Origin) ->
  case http_uri:parse(Origin) of
    {ok, Res} -> string:tokens(element(3, Res), ".");
    _ -> string:tokens(Origin, ".:")
  end.


%% Internal functions
%% ---------------------------------------------------------------------------------
referer(#headers{referer = undefined}) -> null;
referer(#headers{referer = R})         -> iolist_to_binary(R).

ua(undefined) -> null;
ua(Otherwise) -> iolist_to_binary(Otherwise).

user_agent(Arg) ->
  case http_header(Arg, ?XUA_HEADER) of
    undefined -> (Arg#arg.headers)#headers.user_agent;
    XUserAgent -> XUserAgent
  end.

querydata(undefined) -> #{};
querydata(Q)         -> #{querydata => list_to_binary(Q)}.

querydata_cowboy([])   -> #{};
querydata_cowboy(Data) -> #{querydata => Data}.

% if content type is "application/x-www-form-urlencoded" and method is POST, parse post data like queryobj
postobj(#arg{req = #http_request{method = 'POST'}, headers = #headers{content_type = "application/x-www-form-urlencoded"}} = Arg) ->
  Params = yaws_api:parse_post(Arg),
  #{postobj => format_object(Params)};
postobj(_) -> #{}.

postobj_cowboy(Req, Body) ->
  case cowboy_req:header(<<"content-type">>, Req) of
    <<"application/x-www-form-urlencoded">> ->
      #{postobj => cow_qs:parse_qs(Body)};
    _ ->
      #{}
  end.

format_object(Params) ->
  lists:foldl(fun({K, undefined}, Acc) -> maps:put(list_to_binary(K), <<>>, Acc);
                 ({K, V}, Acc) -> maps:put(list_to_binary(K), list_to_binary(V), Acc)
              end, #{}, Params).

multipartobj(#arg{state = {multipart, Parts}}) -> #{multipartobj => Parts};
multipartobj(_)                                -> #{}.



body(Req, Body) ->
  case cowboy_req:header(<<"content-type">>, Req) of
    <<"multipart/form-data", _/binary>> ->
      #{multipartobj => Body};
    _ ->
      #{client_data => Body}
  end.

client_data(undefined, _)                   -> null;
client_data(B, undefined) when is_binary(B) -> B;
client_data(B, Pre) when is_binary(B),
                         is_binary(Pre)     -> <<Pre/binary, B/binary>>.

%% format_cookies/1 searches for cookies and formats them nicely
format_cookies(#headers{cookie = HeaderValues}) ->
  % There can be multiple cookie headers
  format_cookie_header_values(HeaderValues, #{}).

format_cookie_header_values([], Result) ->
  Result;
format_cookie_header_values([HeaderValue | HeaderValues], Result) ->
  Cookies = yaws_api:parse_cookie(HeaderValue),
  ToBinary = fun(V) when is_list(V) -> list_to_binary(V);
                (_) -> null % Use msgpack's null value for things we don't understand
             end,
  KeyValueList = [{ToBinary(Key), ToBinary(Value)} || #cookie{key = Key, value = Value} <- Cookies, is_list(Key)],
  format_cookie_header_values(HeaderValues, maps:merge(Result, maps:from_list(KeyValueList))).

http_headers(H = #headers{}) ->
  [_ | Values] = tuple_to_list(H),              % First element is record tag
  Names = record_info(fields, headers),
  format_http_headers(Names, Values).

format_http_headers(Names, Values) ->
  format_http_headers(Names, Values, #{}).

format_http_headers([], [], Result) ->
  Result;
format_http_headers([_ | Ks], [undefined | Vs], Result) ->
  format_http_headers(Ks, Vs, Result);
format_http_headers([other], [V], Result) ->
  NameValues = [{format_http_header_name(Name), Value} || {http_header, _Num, Name, undefined, Value} <- V],
  {Names, Values} = lists:unzip(group(NameValues)),
  format_http_headers(Names, Values, Result);
format_http_headers(Ks = [authorization | _], [{_, _, V} | Vs], Result) ->
  %% The authorization header has the special format {User, Password, Original}
  %% where the two first elements are extracted from the third for convenience.
  %% Since we're just passing headers through we just need the original
  format_http_headers(Ks, [V | Vs], Result);
format_http_headers([K | Ks], [V | Vs], Result) ->
  format_http_headers(Ks, Vs, maps:put(to_binary(K), to_binary(V), Result)).

format_http_header_name(Name) when is_atom(Name) ->
  string:to_lower(atom_to_list(Name));
format_http_header_name(Name) when is_list(Name) ->
  string:to_lower(Name).


%% @doc
%% group/1 condensates similar headers into one header
%% Groups multiple keys into one key only, with values of repeated keys concatenated by ';'
%% e.g.,
%% ```[{<<"accept-charset">>,"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},
%%  {<<"accept-language">>,"en-US,en;q=0.8"},
%%  {<<"accept-language">>,"en-UK"},
%%  {<<"cache-control">>,"max-age=0"}].'''
%% Will become:
%% ```[{<<"accept-charset">>,"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},
%%  {<<"accept-language">>,"en-US,en;q=0.8;en-UK"},
%%  {<<"cache-control">>,"max-age=0"}].'''
%% @end
group(KeyValues) ->
  group(lists:keysort(1, KeyValues), []).

group([], Result)                        -> lists:reverse(Result);
group([{K, V1}, {K, V2} | Rest], Result) -> group(Rest, [{K, V1 ++ ";" ++ V2} | Result]);
group([{K, V} | Rest], Result)           -> group(Rest, [{K, V} | Result]).

%% @doc Analyzes the request in order to find the originating IP. It tries things successively until it finds a best match.
client_ip(Arg = #arg{headers = Headers}) when Headers /= undefined ->
  case {Headers#headers.x_forwarded_for,
        http_header(Arg, ?XRI_HEADER),
        http_header(Arg, ?XFF_HEADER)} of
    {undefined, undefined, undefined} ->
      %% There are no headers, just pick the IP directly from Yaws
      {{IP1, IP2, IP3, IP4}, _Port} = Arg#arg.client_ip_port,
      lists:flatten(io_lib:format("~b.~b.~b.~b", [IP1, IP2, IP3, IP4]));
    {undefined, undefined, IPList} ->
      %% There is an XFF header, use it
      case ip_number(IPList) of
        "unknown" ->
          lager:info("Can't resolve IP from request ~p, ~s", [Arg, IPList]),
          {{IP1, IP2, IP3, IP4}, _Port} = Arg#arg.client_ip_port,
          lists:flatten(io_lib:format("~b.~b.~b.~b", [IP1, IP2, IP3, IP4]));
        IPNumber -> IPNumber
      end;
    {undefined, IP, _} ->
      %% There is an XRI Header, use it
      IP;
    {IPList, _, _} ->
      %% X-Forwarded-For has been set by yaws, use that!
      case ip_number(IPList) of
        "unknown" ->
          lager:info("Can't resolve IP from request ~p, ~s", [Arg, IPList]),
          {{IP1, IP2, IP3, IP4}, _Port} = Arg#arg.client_ip_port,
          lists:flatten(io_lib:format("~b.~b.~b.~b", [IP1, IP2, IP3, IP4]));
        IPNumber -> IPNumber
      end
  end.

client_ip_cowboy(Req) ->
  case {cowboy_req:header(<<"x-forwarded-for">>, Req),
        cowboy_req:header(<<"x-real-ip">>, Req)} of
    {undefined, undefined} ->
      {{IP1, IP2, IP3, IP4}, _} = cowboy_req:peer(Req),
      lists:flatten(io_lib:format("~b.~b.~b.~b", [IP1, IP2, IP3, IP4]));
    {undefined, Ip} ->
      Ip;
    {Ip, _} ->
      Ip
  end.


to_binary(V) when is_list(V)   -> list_to_binary(V);
to_binary(V) when is_atom(V)   -> to_binary(atom_to_list(V));
to_binary(V) when is_binary(V) -> V.

ip_number(IPList) ->
  case string:chr(IPList, $,) of
    0 -> IPList;
    Index -> string:sub_string(IPList, 1, Index - 1)
  end.

http_header(#arg{headers = H}, Name) ->
  case lists:keyfind(Name, 3, H#headers.other) of
    false -> undefined;
    {http_header, _, Name, _, "nil"} -> undefined;
    {http_header, _, Name, _, "null"} -> undefined;
    {http_header, _, Name, _, Value} -> Value
  end.

request_type(#http_request{method = 'GET'})                     -> <<"GET">>;
request_type(#http_request{method = 'HEAD'})                    -> <<"HEAD">>;
request_type(#http_request{method = 'DELETE'})                  -> <<"DELETE">>;
request_type(#http_request{method = 'PUT'})                     -> <<"PUT">>;
request_type(#http_request{method = 'POST'})                    -> <<"POST">>;
request_type(#http_request{method = 'OPTIONS'})                 -> <<"OPTIONS">>;
request_type(#http_request{method = 'PATCH'})                   -> <<"PATCH">>;
request_type(#http_request{method = Other}) when is_list(Other) -> list_to_binary(Other).

get_protocol_header(Arg) ->
  case http_header(Arg, ?PROTOCOL_HEADER_NAME) of
    "https" -> https;
    _ -> http
  end.

match_white_listed_method(RoutingKey, Method) ->
  [M || M <- proplists:get_all_values(RoutingKey, application:get_env(broen, cors_white_list, [])),
   M == Method].

-spec cors_header(#arg{}) -> string()|'undefined'.
cors_header(Arg) -> http_header(Arg, ?CORS_HEADER).


match_origins(Origin) ->
  lists:any(fun(AllowedOrigin) -> match_origin(Origin, lists:reverse(AllowedOrigin)) end,
            application:get_env(broen, cors_allowed_origins, [])).


match_origin([Part | Rest], [Part | Rest2]) -> match_origin(Rest, Rest2);
match_origin(_, [])                         -> true;
match_origin(_, _)                          -> false.


merge_maps(Maps) -> merge_maps(Maps, #{}).

merge_maps([H | T], Acc) -> merge_maps(T, maps:merge(H, Acc));
merge_maps([], Acc)      -> Acc.

%% Unit tests
%% ---------------------------------------------------------------------------------
cors_test_() ->
  application:set_env(broen, cors_allowed_origins, [
    ["test", "com"],
    ["test2", "com"],
    ["sub", "test3", "com"]
  ]),
  application:set_env(broen, cors_white_list, [
    {<<"allowed.route">>, <<"PUT">>}
  ]),
  fun() ->
    ?assertMatch(allow_origin, check_http_origin(<<"GET">>, "http://www.any-origin.com", <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, "http://www.test.com", <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"DELETE">>, "http://www.test2.com", <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, "http://www.sub.test3.com", <<"some.route">>, "", "")),
    ?assertMatch(unknown_origin, check_http_origin(<<"POST">>, "http://www.other.test3.com", <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, "http://www.something.test.com", <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, "http://www.something.test.com:5000", <<"some.route">>, "", "")),
    ?assertMatch(unknown_origin, check_http_origin(<<"POST">>, "http://www.any-origin.com", <<"some.route">>, "", "")),
    ?assertMatch(unknown_origin, check_http_origin(<<"POST">>, "http://www.any-origin.com", <<"allowed.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"PUT">>, "http://www.any-origin.com", <<"allowed.route">>, "", ""))
  end.

cors_bin_test_() ->
  application:set_env(broen, cors_allowed_origins, [
    [<<"test">>, <<"com">>],
    [<<"test2">>, <<"com">>],
    [<<"sub">>, <<"test3">>, <<"com">>]
  ]),
  application:set_env(broen, cors_white_list, [
    {<<"allowed.route">>, <<"PUT">>}
  ]),
  fun() ->
    ?assertMatch(allow_origin, check_http_origin(<<"GET">>, <<"http://www.any-origin.com">>, <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, <<"http://www.test.com">>, <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"DELETE">>, <<"http://www.test2.com">>, <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, <<"http://www.sub.test3.com">>, <<"some.route">>, "", "")),
    ?assertMatch(unknown_origin, check_http_origin(<<"POST">>, <<"http://www.other.test3.com">>, <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, <<"http://www.something.test.com">>, <<"some.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"POST">>, <<"http://www.something.test.com:5000">>, <<"some.route">>, "", "")),
    ?assertMatch(unknown_origin, check_http_origin(<<"POST">>, <<"http://www.any-origin.com">>, <<"some.route">>, "", "")),
    ?assertMatch(unknown_origin, check_http_origin(<<"POST">>, <<"http://www.any-origin.com">>, <<"allowed.route">>, "", "")),
    ?assertMatch(allow_origin, check_http_origin(<<"PUT">>, <<"http://www.any-origin.com">>, <<"allowed.route">>, "", ""))
  end.
