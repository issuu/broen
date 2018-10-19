-module(routing_SUITE).

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

  WorkingUrl = start_server(ConnInfo, "routing_test.working", fun working_key/3),
  NotFoundUrl = start_server(ConnInfo, "routing_test.not_found", fun not_found_key/3),
  PostUrl = start_server(ConnInfo, "routing_test.post", fun post_key/3),
  timer:sleep(1000),
  [{working_url, WorkingUrl},
   {not_found_url, NotFoundUrl},
   {post_url, PostUrl},
   {non_existent_url, "http://localhost:7085/call/whatisthis/i/dont/even"} | Config].
end_per_suite(_Config) ->
  ok.

all() ->
  ct_helper:all_tests(?MODULE).

test_working_url(Config) ->
  Url = ?config(working_url, Config),
  {ok, {Resp, Props, Payload}} = httpc:request(get, {Url, []}, [], []),
  {_, 200, _} = Resp,
  "application/json" = proplists:get_value("content-type", Props),
  #{<<"message">> := <<"Hello!">>} = jsx:decode(list_to_binary(Payload), [return_maps]).

test_not_found_url(Config) ->
  Url = ?config(not_found_url, Config),
  {ok, {Resp, _Props, _Payload}} = httpc:request(get, {Url, []}, [], []),
  {_, 404, _} = Resp.

test_post_url(Config) ->
  Url = ?config(post_url, Config),
  {ok, {Resp, Props, Payload}} = httpc:request(post, {Url, [], "application/json", jsx:encode(#{data => <<"Hi">>})}, [], []),
  {_, 200, _} = Resp,
  "application/json" = proplists:get_value("content-type", Props),
  #{<<"data">> := <<"Hi">>} = jsx:decode(list_to_binary(Payload), [return_maps]).

test_non_existent_url(Config) ->
  Url = ?config(non_existent_url, Config),
  {ok, {Resp, _Props, _Payload}} = httpc:request(get, {Url, []}, [], []),
  {_, 503, _} = Resp.

start_server(ConnInfo, RoutingKey, Handler) ->
  {ok, Hostname} = inet:gethostname(),
  UrlBit = lists:flatten(string:replace(RoutingKey, ".", "/", all)),
  QueueName = iolist_to_binary([RoutingKey, "-", Hostname]),
  WorkingUrl = "http://localhost:7085/call/" ++ UrlBit,

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

working_key(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"GET">> = maps:get(<<"method">>, Unpacked),
  {reply, jsx:encode(#{
                       media_type => <<"application/json">>,
                       payload => jsx:encode(#{message => <<"Hello!">>})
                     }), <<"application/json">>}.

not_found_key(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"GET">> = maps:get(<<"method">>, Unpacked),
  {reply, jsx:encode(#{
                       status_code => 404,
                       payload => jsx:encode(#{})
                     }), <<"application/json">>}.

post_key(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"POST">> = maps:get(<<"method">>, Unpacked),
  Obj = maps:get(<<"client_data">>, Unpacked),
  {reply, jsx:encode(#{
                       media_type => <<"application/json">>,
                       payload => Obj
                     }), <<"application/json">>}.
