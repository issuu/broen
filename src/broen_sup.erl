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
   {no_ack, true},
   {queue_definitions,
    exchange_defs(application:get_env(broen, servers), application:get_env(broen, defaults, #{}))
  }],

  AMQPRpcClient = amqp_director:ad_client_child_spec(amqp_rpc, ConnInfo, RPCConfig),

  {ok, {{one_for_one, 5, 3600}, [AMQPRpcClient]}}.

conn_info() ->
  {ok, ConnProps} = application:get_env(broen, amqp_connection),
  amqp_director:parse_connection_parameters(ConnProps).

alternate_exchange_def(#{alternate_exchange := Alt}) ->
  [#'exchange.declare'{exchange = Alt, type = <<"topic">>}];
alternate_exchange_def(_) -> [].

exchange_def(#{name := Exch, alternate_exchange := Alt}) ->
  #'exchange.declare'{exchange = Exch, type = <<"topic">>,
                      arguments = [{<<"alternate-exchange">>, longstr, Alt}]};
exchange_def(Exch) ->
  #'exchange.declare'{exchange = Exch, type = <<"topic">>}.

exchange_defs({ok, Servers}, Defaults) ->
  case maps:get(exchange, Defaults, undefined) of
    undefined -> [];
    Exch -> [exchange_def(Exch)] ++ alternate_exchange_def(Exch)
  end ++ exchange_defs(maps:values(Servers)) ++ alternate_exchange_defs(maps:values(Servers)).

exchange_defs([]) -> [];
exchange_defs([#{ exchange := Exch } | Rest]) -> [exchange_def(Exch) | exchange_defs(Rest)];
exchange_defs([_ | Rest]) -> exchange_defs(Rest).

alternate_exchange_defs([]) -> [];
alternate_exchange_defs([#{ exchange := Exch } | Rest]) -> alternate_exchange_def(Exch) ++ alternate_exchange_defs(Rest);
alternate_exchange_defs([_|Rest]) -> alternate_exchange_defs(Rest).
