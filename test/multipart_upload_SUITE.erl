-module(multipart_upload_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("amqp_client/include/amqp_client.hrl").

-include_lib("common_test/include/ct.hrl").

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
  [{timetrap, {seconds, 30}}].

%%--------------------------------------------------------------------
%% @spec init_per_suite(Config0) ->
%%     Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------

init_per_suite(Config) ->
  {ok, _} = application:ensure_all_started(broen),

  {ok, ConnProps} = application:get_env(broen, amqp_connection),
  ConnInfo = amqp_director:parse_connection_parameters(ConnProps),


  {ok, Hostname} = inet:gethostname(),
  RoutingKey = "broen_testing_multipart",
  QueueName = iolist_to_binary([RoutingKey, "-", Hostname]),
  PostUrl = "http://localhost:7085/multipart/" ++ RoutingKey,

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


  %% Can *NOT* start the UploadListener process in the
  %% init_per_... functions because they run in a separate process
  %% which is terminated before running the test case killing the
  %% listener as well
  UploadNotifier = fun(Pid) ->
    Handle = fun(Payload, <<"application/json">>, _Type) ->
      Unpacked = jsx:decode(Payload, [return_maps]),
      MultiPartObj = maps:get(<<"multipartobj">>, Unpacked),
      #{<<"image">> :=
        #{<<"opts">> := _Opts,
          <<"body">> := Body}} = MultiPartObj,
      Pid ! base64:decode(Body),

      {reply, jsx:encode(#{}), <<"application/json">>}
             end,

    amqp_server_sup:start_link(testing_amqp_conn, ConnInfo, AmqpConfig, Handle, 1),

    %% amqp director waits 500 msecs before connecting
    %% See https://github.com/issuu/amqp_director/blob/master/src/amqp_rpc_server2.erl#L73
    timer:sleep(800)
                   end,


  {ok, Dir} = file:get_cwd(),
  TestDataDir = filename:dirname(filename:dirname(Dir)) ++ "/lib/broen/test/data",
  SmallImg = TestDataDir ++ "/header.png",
  LargeImg = TestDataDir ++ "/image_1mb.jpeg",

  [{post_url, PostUrl},
   {upload_notifier, UploadNotifier},
   {small_img, SmallImg},
   {large_img, LargeImg} | Config].

%%--------------------------------------------------------------------
%% @spec end_per_suite(Config0) -> void() | {save_config,Config1}
%% Config0 = Config1 = [tuple()]
%% @end
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
  ok.

%%--------------------------------------------------------------------
%% @spec init_per_group(GroupName, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% GroupName = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
init_per_group(_GroupName, Config) ->
  Config.

%%--------------------------------------------------------------------
%% @spec end_per_group(GroupName, Config0) ->
%%               void() | {save_config,Config1}
%% GroupName = atom()
%% Config0 = Config1 = [tuple()]
%% @end
%%--------------------------------------------------------------------
end_per_group(_GroupName, _Config) ->
  ok.

%%--------------------------------------------------------------------
%% @spec init_per_testcase(TestCase, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% TestCase = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
  UploadNotifier = ?config(upload_notifier, Config),
  UploadNotifier(self()),            % same process as the test case
  Config.

%%--------------------------------------------------------------------
%% @spec end_per_testcase(TestCase, Config0) ->
%%               void() | {save_config,Config1} | {fail,Reason}
%% TestCase = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_TestCase, _Config) ->
  catch (supervisor:terminate_child(amqp_server_sup, testing_amqp_conn)),
  ok.

%%--------------------------------------------------------------------
%% @spec groups() -> [Group]
%% Group = {GroupName,Properties,GroupsAndTestCases}
%% GroupName = atom()
%% Properties = [parallel | sequence | Shuffle | {RepeatType,N}]
%% GroupsAndTestCases = [Group | {group,GroupName} | TestCase]
%% TestCase = atom()
%% Shuffle = shuffle | {shuffle,{integer(),integer(),integer()}}
%% RepeatType = repeat | repeat_until_all_ok | repeat_until_all_fail |
%%              repeat_until_any_ok | repeat_until_any_fail
%% N = integer() | forever
%% @end
%%--------------------------------------------------------------------
groups() ->
  [].

%%--------------------------------------------------------------------
%% @spec all() -> GroupsAndTestCases | {skip,Reason}
%% GroupsAndTestCases = [{group,GroupName} | TestCase]
%% GroupName = atom()
%% TestCase = atom()
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
all() ->
  ct_helper:all_tests(?MODULE).


test_upload_small_img(Config) ->
  ImgPath = ?config(small_img, Config),
  PostUrl = ?config(post_url, Config),
  ct:pal("Curl command: ~p", [curl_cmd(ImgPath, PostUrl)]),
  "200" = os:cmd(curl_cmd(ImgPath, PostUrl)),
  Uploaded = receive D -> D end,
  FileContents = read_file_contents(ImgPath),
  io:format("Uploaded ~p", [Uploaded]),
  io:format("FileContents ~p", [FileContents]),
  Uploaded = FileContents,
  ok.


test_upload_large_img(Config) ->
  ImgPath = ?config(large_img, Config),
  PostUrl = ?config(post_url, Config),
  "200" = os:cmd(curl_cmd(ImgPath, PostUrl)),
  Uploaded = receive D -> D end,
  FileContents = read_file_contents(ImgPath),
  Uploaded = FileContents,
  ok.


%% Helpers
read_file_contents(Path) ->
  {ok, IODev} = file:open(Path, [read, binary]),
  {ok, FileContents} = file:read(IODev, 10 * 1024 * 1024),
  eof = file:read(IODev, 1),
  ok = file:close(IODev),
  FileContents.


curl_cmd(ImgPath, PostUrl) ->
  lists:flatten(io_lib:format("curl -s -o /dev/null -w '%{http_code}' -F 'image=@~s' ~s", [ImgPath, PostUrl])).
