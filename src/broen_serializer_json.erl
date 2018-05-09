-module(broen_serializer_json).
-include_lib("yaws/include/yaws_api.hrl").
-include_lib("eunit/include/eunit.hrl").

%% API
-export([serialize/1,
         deserialize/2]).

-spec serialize(broen_core:broen_request()) -> {term(), broen_core:content_type()}.
serialize(Request) ->
  MappedReq = maps:map(fun(multipartobj, Val) -> handle_multipart(Val); (_, Val) -> Val end, Request),
  {jsx:encode(MappedReq), <<"application/json">>}.

-spec deserialize(term(), broen_core:content_type()) -> {ok, broen_core:broen_response()} | {error, invalid_content_type}.
deserialize(Raw, <<"application/json">>) ->
  Decoded = jsx:decode(Raw, [return_maps]),
  MappedResponse = maps:from_list(lists:map(fun({K, V}) -> {binary_to_atom(K, utf8), V} end, maps:to_list(Decoded))),
  MappedCookies = map_cookies(maps:find(cookies, MappedResponse)),
  {ok, maps:put(cookies, MappedCookies, MappedResponse)};
deserialize(_Raw, _) ->
  {error, invalid_content_type}.

map_cookies(error) -> #{};
map_cookies({ok, Cookies}) ->
  maps:map(fun(_CookieName, Values) ->
    maps:from_list(lists:map(fun({K, V}) -> {binary_to_existing_atom(K, utf8), V} end, maps:to_list(Values)))
           end, Cookies).

handle_multipart({MultipartVal}) when is_list(MultipartVal) ->
  maps:map(fun(<<"body">>, V) -> base64:encode(V); (_K, V) -> handle_multipart(V) end,
           maps:from_list(MultipartVal));
handle_multipart(Else) -> Else.

serializer_test_() ->
  Request = #{appmoddata => <<"broen_testing_multipart">>, auth_data => [],
              client_data => null, client_ip => <<"127.0.0.1">>, cookies => #{},
              fullpath =>
              <<"some_fullpath">>,
              http_headers =>
              #{<<"accept">> => <<"*/*">>, <<"content_length">> => <<"1739">>,
                <<"content_type">> =>
                <<"multipart/form-data; boundary=------------------------f991051bb9b3059a">>,
                <<"cookie">> => <<>>, <<"expect">> => <<"100-continue">>,
                <<"host">> => <<"localhost:7083">>,
                <<"user_agent">> => <<"curl/7.54.0">>},
              method => <<"POST">>,
              queryobj => #{}, referer => null, request => <<"POST">>,
              multipartobj =>
              {[{<<"image">>,
                 {[{<<"opts">>,
                    {[{<<"filename">>, <<"header.png">>},
                      {<<"content_type">>, <<"application/octet-stream">>}]}},
                   {<<"body">>,
                    <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 175, 0,
                      236, 152, 203, 110, 195, 48, 12, 4, 41, 217, 150, 109, 229, 255>>}]}}]},
              routing_key => <<"broen_testing_multipart">>,
              useragent => <<"curl/7.54.0">>},
  {Serialized, _} = serialize(Request),
  {ok, Deserialized} = deserialize(Serialized, <<"application/json">>),
  NoMultipartReq = maps:map(fun remove_multipart/2, Request),
  NoMultipartDeserialized = maps:map(fun remove_multipart/2, Deserialized),
  fun() ->
    ?assert(is_binary(Serialized)),
    ?assertMatch(NoMultipartReq, NoMultipartDeserialized)
  end.

remove_multipart(multipartobj, _) -> #{};
remove_multipart(_, Val)          -> Val.
