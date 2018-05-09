-module(broen_mod_res).

-include_lib("yaws/include/yaws_api.hrl").

-export([out/1]).

out(Arg) ->
  broen_core:handle(Arg, <<"http_exchange">>, broen_mod:default_cookie_path(Arg#arg.server_path),
                    [keep_dots_in_routing_keys, {timeout, 50}]).
