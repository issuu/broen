%%% @hidden
-module(broen_mod_res).

-export([init/2]).

init(Req0, State) ->
  Ret = broen_core:handle(Req0, <<"http_exchange">>, broen_mod:default_cookie_path(cowboy_req:path(Req0)),
                                 [keep_dots_in_routing_keys, {timeout, 50}]),
  {ok, Ret, State}.
