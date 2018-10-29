%%% ---------------------------------------------------------------------------------
%%% @private
%%% @doc
%%% The main application module
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_app).
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).


%% Application callbacks
%% ---------------------------------------------------------------------------------
start(_StartType, _StartArgs) ->
  broen_core:register_metrics(),
  {ok, Pid} = broen_sup:start_link(),
  start_cowboy(),
  {ok, Pid}.


stop(_State) ->
  ok.

%% Internal functions
%% ---------------------------------------------------------------------------------
start_cowboy() ->
  {ok, Port} = application:get_env(broen, port),
  {ok, InternalPort} = application:get_env(broen, internalport),
  Dispatch = cowboy_router:compile([
                                     {'_', [
                                       {"/call/[...]", broen_mod, []},
                                       {"/res/[...]", broen_mod_res, []},
                                       {"/multipart/[...]", broen_mod, []}
                                     ]}
                                   ]),
  InternalDispatch = cowboy_router:compile([
                                             {'_', [
                                               {"/internal_call/[...]", broen_mod_internal, []}
                                             ]}]),

  {ok, _} = cowboy:start_clear(call_handler, [{port, Port}], #{env => #{dispatch => Dispatch}}),
  {ok, _} = cowboy:start_clear(internal_handler, [{port, InternalPort}], #{env => #{dispatch => InternalDispatch}}).
