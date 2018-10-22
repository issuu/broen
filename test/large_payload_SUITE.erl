-module(large_payload_SUITE).

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

  LargeUrl = start_server(ConnInfo, "large_test.endpoint", fun large_endpoint/3),
  timer:sleep(1000),
  [{large_url, LargeUrl} | Config].
end_per_suite(_Config) ->
  ok.

all() ->
  ct_helper:all_tests(?MODULE).

test_large_payload(Config) ->
  Url = ?config(large_url, Config),
  LargePayload = get_file_content(),
  {ok, {Resp, Props, Payload}} = httpc:request(post, {Url, [], "application/json", LargePayload}, [], []),
  {_, 200, _} = Resp,
  "application/json" = proplists:get_value("content-type", Props),
  #{<<"result">> := true} = jsx:decode(list_to_binary(Payload), [return_maps]).


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

large_endpoint(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"POST">> = maps:get(<<"method">>, Unpacked),
  Obj = maps:get(<<"client_data">>, Unpacked),

  LargePayload = get_file_content(),

  {reply, jsx:encode(#{
                       media_type => <<"application/json">>,
                       payload => jsx:encode(#{result => Obj =:= LargePayload})
                     }), <<"application/json">>}.


get_file_content() ->
  {ok, Dir} = file:get_cwd(),
  TestDataDir = filename:dirname(filename:dirname(Dir)) ++ "/lib/broen/test/data",
  {ok, LargePayload} = file:read_file(TestDataDir ++ "/big_payload.json"),
  LargePayload.
