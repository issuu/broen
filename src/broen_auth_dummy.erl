-module(broen_auth_dummy).
-include_lib("yaws/include/yaws_api.hrl").

%% API
-export([authenticate/1]).


-spec authenticate(#arg{}) -> {ok, term(), term()} | {error, {csrf_verification_failed, list(term())}} | {error, term()}.
authenticate(_Arg) ->
  {ok, [], []}.
