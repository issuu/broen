%%% ---------------------------------------------------------------------------------
%%% @private
%%% @doc
%%% The main application module
%%% @end
%%% ---------------------------------------------------------------------------------
-module(broen_app).

-include_lib("yaws/include/yaws.hrl").

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1, prep_stop/1]).


%% Application callbacks
%% ---------------------------------------------------------------------------------
start(_StartType, _StartArgs) ->
  broen_core:register_metrics(),
  {ok, Pid} = broen_sup:start_link(),
  ok = start_yaws(),
  start_cowboy(),
  {ok, Pid}.

prep_stop(State) ->
  ok = stop_yaws(),
  State.

stop(_State) ->
  ok.

%% Internal functions
%% ---------------------------------------------------------------------------------
stop_yaws() ->
  {ok, GC, _Groups} = yaws_api:getconf(),
  ok = yaws_api:setconf(GC, []),
  ok.

start_cowboy() ->
  Dispatch = cowboy_router:compile([
                                     {'_', [
                                       {"/call/[...]", broen_mod, []}
                                     ]}
                                   ]),
  {ok, _} = cowboy:start_clear(my_http_listener, [{port, 7085}], #{env => #{dispatch => Dispatch}}).

start_yaws() ->
  {ok, Port} = application:get_env(broen, port),
  {ok, InternalPort} = application:get_env(broen, internalport),
  {ok, Listen} = application:get_env(broen, listen),
  {ok, ServerName} = application:get_env(broen, server_name),
  {ok, LogDir} = application:get_env(broen, log_dir),
  {ok, PartialPostSize} = application:get_env(broen, partial_post_size),
  {ok, YawsFlags} = application:get_env(broen, yaws_flags),

  AppMods = [{"/call", broen_mod},
             {"/res", broen_mod_res},
             {"/multipart", broen_mod_multipart}],
  InternalAppMods = [{"/internal_call", broen_mod_internal}],
  BaseConfig = yaws_config:make_default_gconf([], false),
  GlobalConfig = BaseConfig#gconf{logdir = filename:absname(LogDir),
                                  flags  = YawsFlags,
                                  yaws   = "emfiws/1.b.334.11 (Solaris)"},
  DocRoot = filename:join([code:priv_dir(broen), "webroot"]),
  ServerConfig = #sconf{port              = Port,
                        listen            = Listen,
                        servername        = ServerName,
                        docroot           = DocRoot,
                        partial_post_size = PartialPostSize,
                        errormod_crash    = broen_server_crash_handler,
                        deflate_options   = #deflate{mime_types = compressible_media_types()},
                        appmods           = AppMods},
  InternalServerConfig = #sconf{port              = InternalPort,
                                listen            = Listen,
                                servername        = ServerName,
                                docroot           = DocRoot,
                                partial_post_size = PartialPostSize,
                                errormod_crash    = broen_server_crash_handler,
                                deflate_options   = #deflate{mime_types = compressible_media_types()},
                                appmods           = InternalAppMods},
  yaws_api:setconf(GlobalConfig,
                   [[?sc_set_deflate(ServerConfig, true)],
                    [?sc_set_deflate(InternalServerConfig, true)]]),
  ok.

compressible_media_types() ->
  [{"application", "javascript"},
   {"application", "json"},
   {"application", "msword"},
   {"application", "pdf"},
   {"application", "postscript"},
   {"application", "rtf"},
   {"application", "xml"},
   {"application", "x-dvi"},
   {"application", "x-javascript"},
   {"text", all}].
