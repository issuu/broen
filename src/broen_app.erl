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
  Listeners = application:get_env(broen, runtime_listeners, []),
  lists:foreach(fun (Pid) -> cowboy:stop_listener(Pid) end, Listeners),
  ok.

%% Internal functions
%% ---------------------------------------------------------------------------------
start_cowboy() ->
  Defaults = maps:merge(
    #{
      keep_dots_in_routing_keys => false,
      num_acceptors => 10,
      max_connections => 1024},
    application:get_env(broen, defaults, #{})),
  {ok, Servers} = application:get_env(broen, servers),
  Listeners = [
    start_server(Server, Defaults)
    || Server <- maps:to_list(Servers)
  ],
  application:set_env(broen, runtime_listeners, Listeners).

start_server({ServerName, #{paths := Paths} = Server}, Defaults) ->
  Port = conf(port, [Server, Defaults]),
  NumAcceptors = conf(num_acceptors, [Server, Defaults]),
  MaxConns = conf(max_connections, [Server, Defaults]),
  Routes = make_paths(maps:to_list(Paths), [Server, Defaults]),
  Dispatch = cowboy_router:compile([{'_', Routes}]),
  CowboyOpts = maps:merge(#{
    env => #{dispatch => Dispatch},
    stream_handlers => [cowboy_compress_h, cowboy_stream_h]
  }, conf_default(cowboy_opts, [Server, Defaults], #{})),
  {ok, _ListenerPid} = cowboy:start_clear(
    ServerName,
    [{num_acceptors, NumAcceptors}, {max_connections, MaxConns}, {port, Port}],
    CowboyOpts),
  ServerName.

make_paths([], _) -> [];
make_paths([{Path, Conf}|Rest], Defaults) ->
  [compile_route(Path, [Conf | Defaults]) | make_paths(Rest, Defaults)].

compile_route(Path, Conf) ->
  HandlerOpts = #{
    exchange => exchange_name(Conf),
    serializer_mod => conf(serializer_mod, Conf),
    auth_mod => conf(auth_mod, Conf),
    partial_post_size => conf(max_multipart_size, Conf),
    timeout => conf(timeout, Conf),
    keep_dots_in_routing_keys => conf(keep_dots_in_routing_keys, Conf)
  },
  {iolist_to_binary([Path, <<"/[...]">>]), broen_mod, HandlerOpts}.

exchange_name(Confs) ->
  case conf(exchange, Confs) of
    #{name := Exch} -> Exch;
    Exch -> Exch
  end.

conf(Key, Envs) ->
  case conf_default(Key, Envs, not_found) of
    not_found -> throw({configuration_missing, Key});
    Res -> Res
  end.

conf_default(_, [], Default) -> Default;
conf_default(Key, [HD|Rest], Default) ->
  case maps:is_key(Key, HD) of
    true -> maps:get(Key, HD);
    false -> conf_default(Key, Rest, Default)
  end.
