-module(auth_mod_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("amqp_client/include/amqp_client.hrl").
-include_lib("yaws/include/yaws_api.hrl").

-include_lib("common_test/include/ct.hrl").

suite() ->
  [{timetrap, {seconds, 30}}].

init_per_suite(Config) ->
  {ok, _} = application:ensure_all_started(broen),
  {ok, OldAuthMod} = application:get_env(broen, auth_mod),
  application:set_env(broen, auth_mod, ?MODULE),

  {ok, ConnProps} = application:get_env(broen, amqp_connection),
  ConnInfo = amqp_director:parse_connection_parameters(ConnProps),

  AuthenticatedUrl = start_server(ConnInfo, "auth_test.auth_url", fun auth_req/3),
  HttpsUrl = start_server(ConnInfo, "auth_test.https", fun https_req/3),
  timer:sleep(1000),
  [{url, AuthenticatedUrl}, {https_url, HttpsUrl}, {old_auth, OldAuthMod} | Config].
end_per_suite(Config) ->
  AuthMod = ?config(old_auth, Config),
  application:set_env(broen, auth_mod, AuthMod),
  ok.

all() ->
  ct_helper:all_tests(?MODULE).

test_auth_module(Config) ->
  Url = ?config(url, Config),
  {ok, {Resp, Props, Payload}} = httpc:request(get, {Url, []}, [], []),
  {_, 200, _} = Resp,
  "application/json" = proplists:get_value("content-type", Props),
  #{<<"message">> := <<"Hello!">>} = jsx:decode(list_to_binary(Payload), [return_maps]).

test_https(Config) ->
    Url = ?config(https_url, Config),
    {ok, {Resp, Props, Payload}} = httpc:request(get, {Url, [{"X-Forwarded-Proto", "https"}]}, [], []),
    {_, 200, _} = Resp,
    "application/json" = proplists:get_value("content-type", Props),
    #{<<"message">> := <<"Hello!">>} = jsx:decode(list_to_binary(Payload), [return_maps]).

start_server(ConnInfo, RoutingKey, Handler) ->
  {ok, Hostname} = inet:gethostname(),
  UrlBit = lists:flatten(string:replace(RoutingKey, ".", "/", all)),
  QueueName = iolist_to_binary([RoutingKey, "-", Hostname]),
  WorkingUrl = "http://localhost:7083/call/" ++ UrlBit,

  AmqpConfig = [{exchange, <<"http_exchange">>},
                {consume_queue, QueueName},
                no_ack,
                {queue_definitions, [#'exchange.declare'{exchange = <<"http_exchange">>,
                                                         type     = <<"topic">>},
                                     #'queue.declare'{queue       = QueueName,
                                                      exclusive   = true,
                                                      auto_delete = true
                                     },
                                     #'queue.bind'{exchange    = <<"http_exchange">>,
                                                   queue       = QueueName,
                                                   routing_key = iolist_to_binary([RoutingKey, ".#"])}
                ]}],
  {ok, Pid} = amqp_server_sup:start_link(list_to_atom(RoutingKey ++ "_test"), ConnInfo, AmqpConfig, Handler, 1),
  unlink(Pid),
  WorkingUrl.

auth_req(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"GET">> = maps:get(<<"method">>, Unpacked),
  #{<<"authenticated">> := true} = maps:get(<<"auth_data">>, Unpacked),
  {reply, jsx:encode(#{
                       media_type => <<"application/json">>,
                       payload => jsx:encode(#{message => <<"Hello!">>})
                     }), <<"application/json">>}.


https_req(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  case maps:get(<<"protocol">>, Unpacked) of
    <<"https">> ->
      {reply, jsx:encode(#{
                            media_type => <<"application/json">>,
                            payload => jsx:encode(#{message => <<"Hello!">>})
                          }), <<"application/json">>};
    _ ->
      {reply, jsx:encode(#{
                            media_type => <<"application/json">>,
                            payload => jsx:encode(#{error => <<"Wrong!">>})
                          }), <<"application/json">>}
  end.

authenticate(_Arg) ->
  {ok, #{authenticated => true}, []}.
