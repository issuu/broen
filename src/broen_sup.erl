%%% ---------------------------------------------------------------------------------
%%% @private
%%% @doc
%%% The main supervisor for broen.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_sup).
-behaviour(supervisor).

-include_lib("amqp_client/include/amqp_client.hrl").

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
  ConnInfo = conn_info(),
  RPCConfig =
  [{reply_queue,
    iolist_to_binary([<<"replyq-">>,
                      amqp_director:mk_app_id('broen.rpc_client')])},
   no_ack,
   {queue_definitions,
    [
      #'exchange.declare'{exchange = <<"http_exchange">>, type = <<"topic">>},
      #'exchange.declare'{exchange = <<"http_exchange_internal_alt">>, type = <<"topic">>},
      #'exchange.declare'{exchange  = <<"http_exchange_internal">>, type = <<"topic">>,
                          arguments = [{<<"alternate-exchange">>, longstr, <<"http_exchange_internal_alt">>}]}
    ]}],


  AmqpClient = amqp_director:ad_client_child_spec(amqp_client_endpoint, ConnInfo, [no_ack]),

  AMQPRpcClient = amqp_director:ad_client_child_spec(amqp_rpc, ConnInfo, RPCConfig),


  {ok, {{one_for_all, 5, 3600}, [AMQPRpcClient, AmqpClient]}}.

conn_info() ->
  {ok, ConnProps} = application:get_env(broen, amqp_connection),
  amqp_director:parse_connection_parameters(ConnProps).
