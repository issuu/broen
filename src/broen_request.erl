%%% ---------------------------------------------------------------------------------
%%% @doc
%%% This module handles building broen requests out of Yaws data.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_request).

-include_lib("eunit/include/eunit.hrl").

%% API
-export([build_request/3,
         check_http_origin/2]).

-define(XFF_HEADER, "X-Forwarded-For").
-define(XRI_HEADER, "X-Real-Ip").
-define(XUA_HEADER, "X-User-Agent").
-define(PROTOCOL_HEADER_NAME, "X-Forwarded-Proto").
-define(CORS_HEADER, "Origin").

-spec build_request(map(), binary(), list(broen_core:broen_other_key())) -> broen_core:broen_request().
build_request(Req, RoutingKey, AuthData) ->
  {Body, ReadReq} = get_body(Req),
  Request =
    merge_maps([
                 querydata(cowboy_req:qs(ReadReq)),
                 postobj(ReadReq, Body),
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
                   useragent => cowboy_req:header(<<"user-agent">>, ReadReq),
                   client_ip => iolist_to_binary(client_ip(ReadReq)),
                   routing_key => RoutingKey,
                   queryobj => maps:from_list(cowboy_req:parse_qs(Req)),
                   auth_data => AuthData}
               ]),
  maps:map(fun(_K, undefined) -> null;
              (client_data, <<>>) -> null;
              (_K, V) -> V end, Request).

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
      get_body(Req, <<SoFar/binary, Data/binary>>)
  end.

-spec check_http_origin(map(), binary()) -> {undefined | binary(), 'same_origin'|'allow_origin'|'unknown_origin'}.
check_http_origin(Req, RoutingKey) ->
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
  end.


%% Internal functions
%% ---------------------------------------------------------------------------------
querydata(<<>>) -> #{};
querydata(Data) -> #{querydata => Data}.

postobj(Req, Body) ->
  case cowboy_req:header(<<"content-type">>, Req) of
    <<"application/x-www-form-urlencoded">> ->
      #{postobj => cow_qs:parse_qs(Body)};
    _ ->
      #{}
  end.


body(Req, Body) ->
  case cowboy_req:header(<<"content-type">>, Req) of
    <<"multipart/form-data", _/binary>> ->
      #{multipartobj => Body,
        client_data => null};
    _ ->
      #{client_data => Body}
  end.


client_ip(Req) ->
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

match_white_listed_method(RoutingKey, Method) ->
  [M || M <- proplists:get_all_values(RoutingKey, application:get_env(broen, cors_white_list, [])),
   M == Method].


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
