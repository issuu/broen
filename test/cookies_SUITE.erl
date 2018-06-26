-module(cookies_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("amqp_client/include/amqp_client.hrl").

-include_lib("common_test/include/ct.hrl").

suite() ->
  [{timetrap, {seconds, 30}}].

init_per_suite(Config) ->
  {ok, _} = application:ensure_all_started(broen),

  {ok, ConnProps} = application:get_env(broen, amqp_connection),
  ConnInfo = amqp_director:parse_connection_parameters(ConnProps),

  WorkingUrl = start_server(ConnInfo, "routing_test.cookies", fun cookies/3),
  timer:sleep(1000),
  [{url, WorkingUrl} | Config].
end_per_suite(_Config) ->
  ok.

all() ->
  ct_helper:all_tests(?MODULE).

test_cookies(Config) ->
  Url = ?config(url, Config),
  {ok, {Resp, Props, Payload}} = httpc:request(get, {Url, []}, [], []),
  {_, 200, _} = Resp,
  "application/json" = proplists:get_value("content-type", Props),
  "test_cookie=11; Version=1; Domain=mine; Path=/; Expires=Sun, 17 Jan 2038 12:34:56 GMT; Secure" = proplists:get_value("set-cookie", Props),

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

cookies(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"GET">> = maps:get(<<"method">>, Unpacked),
  {reply, jsx:encode(#{
                       media_type => <<"application/json">>,
                       cookies => #{<<"test_cookie">> => #{value => <<"11">>,
                                                           domain => <<"mine">>,
                                                           secure => true,
                                                           path => <<"/">>}},
                       payload => jsx:encode(#{message => <<"Hello!">>})
                     }), <<"application/json">>}.
