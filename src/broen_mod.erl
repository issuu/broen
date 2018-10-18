%%% @doc false
-module(broen_mod).

-include_lib("yaws/include/yaws_api.hrl").

-export([out/1]).
-export([init/2]).
-export([default_cookie_path/1]).

out(Arg) ->
  io:format("~p~n", [Arg#arg.server_path]),
 broen_core:handle(Arg, <<"http_exchange">>, default_cookie_path(Arg#arg.server_path), []).

-spec default_cookie_path(string()) -> binary().
default_cookie_path(ServerPath) when is_binary(ServerPath) ->
  case binary:split(ServerPath, <<"/">>, [global]) of
    [<<>>, First, Second | _] -> <<"/", First/binary, "/", Second/binary>>;
    _ -> ServerPath
  end;
default_cookie_path(ServerPath) ->
  %% Use first two path levels in cookies
  case string:tokens(ServerPath, "/") of
    [First, Second | _] -> list_to_binary(["/", First, "/", Second]);
    _ -> list_to_binary(ServerPath) % None or one level
  end.

init(Req0, State) ->
  io:format("~p~n", [cowboy_req:path(Req0)]),
  Ret = broen_core:handle_cowboy(Req0, <<"http_exchange">>, default_cookie_path(cowboy_req:path(Req0)), []),
  {ok, Ret, State}.