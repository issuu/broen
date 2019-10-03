%%% @doc false
-module(broen_mod).

-export([init/2]).
-export([default_cookie_path/1]).

-spec default_cookie_path(binary()) -> binary().
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
  Ret = broen_core:handle(Req0, State, default_cookie_path(cowboy_req:path(Req0))),
  {ok, Ret, State}.
