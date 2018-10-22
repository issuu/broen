%%% ---------------------------------------------------------------------------------
%%% @doc
%%% The dummmy authentication module.
%%% This module is an example of an authentication plug-in that broen can be configured
%%% to use. It does not do anything, but gives an example of callback implementation.
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_auth_dummy).

%% API
-export([authenticate/1]).


-spec authenticate(map()) -> {ok, term(), term()} | {error, {csrf_verification_failed, list(term())}} | {error, term()}.
authenticate(_Arg) ->
  {ok, [], []}.
