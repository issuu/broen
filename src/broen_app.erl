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
  Defaults = application:get_env(broen, defaults, #{}),
  {ok, Servers} = application:get_env(broen, servers),
  lists:foreach(fun (Server) -> start_server(Server, Defaults#{keep_dots_in_routing_keys => false}) end, maps:to_list(Servers)).

start_server({ServerName, #{paths := Paths} = Server}, Defaults) ->
  Port = conf(port, [Server, Defaults]),
  Routes = make_paths(maps:to_list(Paths), [Server, Defaults]),
  Dispatch = cowboy_router:compile([{'_', Routes}]),
  {ok, _} = cowboy:start_clear(
    ServerName,
    [{num_acceptors, 100}, {max_connections, 10000}, {port, Port}],
    #{
      env => #{dispatch => Dispatch},
      stream_handlers => [cowboy_compress_h, cowboy_stream_h]}),
  ok.

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

conf(Key, []) -> throw({configuration_missing, Key});
conf(Key, [HD|Rest]) ->
  case maps:is_key(Key, HD) of
    true -> maps:get(Key, HD);
    false -> conf(Key, Rest)
  end.
