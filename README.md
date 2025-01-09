Broen 🇩🇰🌉🇸🇪
==================
[![Build Status](https://travis-ci.org/issuu/broen.svg?branch=master)](https://travis-ci.org/issuu/broen)
[![Hex.pm Version](http://img.shields.io/hexpm/v/broen.svg?style=flat)](https://hex.pm/packages/broen)

The HTTP/AMQP bridge library that allows you to change your HTTP requests into AMQP RPC calls.

## Broen >= 3.1
Added support for prometheus metrics, see test/sys.config. Only iff app env `broen.prometheus.prefix` have been defined.

## Broen >= 3.0
We dropped support for `erlang 20`. Minimum required version is `21` now.

## Broen >= 2.0
Since 2.0 Broen is `cowboy` based, which also means it is [available on Hex!](https://hex.pm/packages/broen)



## Overview
`broen` turns any HTTP requests into a AMQP message, using the path of the
HTTP request for the AMQP routing key. It is primarily designed to serve API
requests, but it is possible to serve any content through it. It has been
battletested through years of service here at Issuu, where we use `broen` to
route frontend requets to the right microservice-backend.

For example, A GET request on `/hello/service/42?foo=bar` is turned into a message with routing-key `hello.service.42`, and will contain `method=<<"GET">>` and `querydata=<<"foo=bar">>`. See [Request section](#request) for more information.

`broen` provides:
* Web server using [cowboy](https://github.com/ninenines/cowboy)
* Forwarding of HTTP requests to an AMQP broker
* Handling of multipart requests
* Optional authentication of requests
* Configurable serialization/deserialization of AMQP messages
* CORS protection
* Metrics using [folsom](https://hex.pm/packages/folsom)

## Endpoints (since v3)
Since version `3.0.0`, `broen` is configurable. Here is a (not-so-minimal) example:

```erlang
...
{broen, [
  % toplevel default configuration
  {defaults, #{
    % effectively disable multipart by default
    max_multipart_size => 0,
    serializer_mod => broen_serializer_json,
    % 5s timeout
    timeout => 5000,
    % where to send broen requests
    exchange => <<"my_exchange">>
  }},
  {servers, #{
    api_srv => #{
      auth_mod => user_auth,
      port => 8080,
      paths => #{
        <<"/api">> => #{},
        <<"/important">> => #{
          exchange => #{
            name => <<"another_exch">>,
            alternate_exchange => <<"another_exch_deadlettering">>},
          timeout => 10000
        }
      }
    },
    backoffice_srv => #{
      auth_mod => backoffice_auth,
      port => 8081,
      timeout => 30000,
      paths => #{
        <<"/backoffice">> => #{}
      }
    }
  }}
]},
...
```

This will configure `broen` to spawn two servers (with default timeout of `5s`, `broen_serializer_json` as serializer and `my_exchange` as exchange):
- `api_srv` on port `8080`, which uses the `user_auth` module as `auth_mod` which has two paths:
  * `/api`
  * `/important`, that overrides the default timeout to `10s` and specifies exchange `another_exch`, configured with dead-lettering
- `backoffice_srv` on port `8081`, which uses the `backoffice_auth` as `auth_mod` and `30s` timeout and a single path `/backoffice`.

All pieces of configuration (except the server `port`, which is specific to the `servers` map items) can be specified down to the `path` level. The configurations keys are:

- `auth_mod`: the authentication module that allows for optional authentication of each request. The authentication module will receive the HTTP request coming from the outside and can return arbitrary data that then will be attached to the `broen` request forwarded to AMQP.
- `serializer_mod`: allows defining of arbitrary serialization protocols, that can be custom to your organisation. The `broen` client services will have to implement the same protocol. `broen` ships with a default JSON serializer.
- `timeout`: requests timeout, in milliseconds.
- `exchange`: to which `amqp` exchange to send the requests. Can be just a `binary` or a map `#{name => binary(), alternate_exchange => binary()}`. The `alternate_exchange` will be used to send requests that could not be handled in the primary exchange.
- `max_multipart_size`: maximum multipart post size (in bytes)

## Configuration
The minimal `broen` config should can look like this:

```erlang
{broen, [{amqp_connection,
           [{host, "localhost"},
            {port, undefined},
            {username, <<"guest">>},
            {password, <<"guest">>}]},
          {listen, {0, 0, 0, 0}},
          {cors_white_list, []},
          {servers, #{
            api_srv => #{
              port => 7083,
              serializer_mod => broen_serializer_json,
              auth_mod => broen_auth_dummy,
              exchange => <<"http_exchange">>,
              timeout => 5000,
              max_multipart_size => 0,
              paths => #{ <<"/call">> => #{} }
            }
          }}
]}
```

This defines a connection to a local AMQP broker with default guest/guest login, the IP address of the `broen` server as well as defining `/call` endpoint on port `7083`.

All configuration parameters are as follow:

```erlang
{broen, [
    {amqp_connection, [
      {host, "amqp"},
      {port, undefined},
      {username, <<"myuser">>},
      {password, <<"secretpassword">>}
    ]},
    {listen, {0, 0, 0, 0}},
    {cors_white_list, [
      {<<"friendly.request">>, <<"POST">>}
    ]},
    {cors_allowed_origins, [
      [<<"mybroen">>, <<"com">>],
      [<<"//mybroen">>, <<"com">>],
    ]},
    {metric_groups, [
      "myurl",
      "myotherurl"
    ]},
    {defaults, ...},
    {servers, ...}
  ]}
  ```
  Where:
  * `amqp_connection :: [{host, string()}, {port :: non_neg_integer() | undefined}, {username, binary()}, {password, binary()}]` - The configuration for the connection to the RabbitMQ broker
  * `listen :: inet:ip4_address()` - Defines the IP address the server will listen on
  * `cors_white_list :: list({binary(), http_method()})` - Defines routing keys that are exempt from CORS protection. Defined as a list of tuples, where the first element is the routing key (URL) and the second one is the HTTP method. Can be one `<<"POST">>`, `<<"PUT">>`, `<<"DELETE">>` and `<<"PATCH">>` (`<<"GET">>` and `<<"OPTIONS">>` are exempt from CORS protection)
  * `cors_allowed_origins :: list(list(regex()))` - List of all origins for which CORS protection does not apply. The origins must be split by the `.` in the URL so e.g. `mybroen.com` should be defined as `["mybroen", "com"]` and `*.mybroen.com` can be defined as `["//mybroen", "com"]`
  * `metric_groups :: list(string())` - Defines the URLs for which automatic `folsom` metrics wil be taken. Any URL called that matches any of the defined ones will be logged in the metrics. New metrics can also be discovered: if a requests for an unknown group is successfully handled, `broen` will start collecting metrics for that group too. Only the first part of the routing key is needed here.
  * `defaults` and `servers` have been discussed in the `Endpoint` section.

## Metrics
`broen` uses [folsom](https://hex.pm/packages/folsom) to record metrics. For each URL called, that is in the `metric_groups` list `broen` will record the following metrics:
  * `broen_core.query.<url>`
  * `broen_core.query.<url>.timeout`
  * `broen_core.query.<url>.latency`
Any other URL (i.e. not in `metric_group`)


Additionally `broen` also records the following metrics:
  * `broen_core.success` - When the RPC call returns
  * `broen_core.failure.500` - When `broen` returns a `500` code. This happens if RPC fails or the RPC response is of wrong type.
  * `broen_core.failure.503` - When `broen` cannot forward the message as RabbitMQ broker cannot find the route, i.e. there is no service listening to that path
  * `broen_auth.failure` - When the authentication module returns an error.

You can add any other functionality on top of `folsom` that will e.g. forward the metrics to statsd.

## Serializers
`broen` allows you to define your own serializer module as needed. This allows for full customization of the protocol between `broen` and the clients. A serializer must implement the following two functions:

```erlang
-spec serialize(broen_core:broen_request()) -> {Serialized :: binary(), broen_core:content_type()}.
```
that takes a `broen_request()` and returns serialized content along with its MIME content type (that will be forwarded to the clients, so a serializer could support multiple content types).

```erlang
-spec deserialize(binary(), broen_core:content_type()) -> {ok, broen_core:broen_response()} | {error, invalid_content_type}.
```
that takes serialized blob with its content type and returns a `broen_response()`.

### Common types
Types used by both responses and requests are defined as follows:
```erlang
-type broen_string() :: unicode:unicode_binary().
-type broen_nullable_string() :: unicode:unicode_binary() | null.
-type broen_object() :: #{broen_string() => broen_string()}.
```

### Request
The request type is defined as follows (see the [Erlang type documentation](http://erlang.org/doc/reference_manual/typespec.html#id79546) for details )
```erlang
-type broen_request() :: #{
              cookies := broen_object(),                % Cookies attached to the HTTP request
              http_headers := broen_object(),           % HTTP request headers
              request := broen_string(),                % The HTTP method
              method := broen_string(),                 % Same as above
              client_data := broen_nullable_string(),
              fullpath := broen_string(),               % Full path of the request
              appmoddata := broen_string(),             % The URL that is turned into the routing key (i.e. what follows /call)
              referer := broen_nullable_string(),       % The referer URL
              useragent := broen_string(),              % User agent data
              client_ip := broen_string(),              % IP of the client
              routing_key := broen_string(),            % The routing key the request will be sent to
              queryobj := broen_object(),               % The query object containing the query parameters
              auth_data := term(),                      % Data returned by the authentication module
              querydata => broen_string(),              % Same as queryobj, but in a string format
              postobj => broen_object(),                % Data attached to a POST request
              multipartobj => term()}.                  % Data for the multipart request
```

The serializer may choose to ommit any of these fields as required, but it must return the serialized request in binary format and the MIME content type.

### Response
The response type is defined as follow:
```erlang
-type broen_response() :: #{
              payload := term(),                        % The payload of the response
              status_code => integer(),                 % Status code of the response
              media_type => content_type(),             % The MIME content type of the payload
              cookies => broen_cookies(),               % Additional cookies to be sent to user
              cookie_path => broen_string(),            % The cookie path
              headers => broen_object()}                % Additional headers for the HTTP response
  | #{redirect := unicode:unicode_binary()}.            % Used to send a redirect to the given URL
```
The response can include the above fields. The serializer is meant to deserialize the binary format, given the content type in the AMQP message and return that map.

The cookies must follow this format:

```erlang
-type cookie_name() :: broen_string().

-type cookie_value() :: #{
    value := broen_string(),
    domain => broen_string(),
    path => broen_string(),
    http_only => boolean(),
    secure => boolean(),
    expires => broen_string()}.
-type broen_cookies() :: #{cookie_name() => cookie_value()}.
```

## Authentication
`broen` allows for an optional authentication mechanism for each request. The authentication module can be plugged in by using `auth_mod` configuration option. The authentication module will receive the raw request in the `cowboy` format and can then perform any operations. By default `broen` ships with `broen_auth_dummy` module, which simply does nothing.

An authentication module must implement the following function:
```erlang
-type cookies() :: [{Name :: binary(), #{value := binary(), max_age => integer(), path => binary(), domain => binary(), secure => boolean(), http_only => boolean()}}]
-spec authenticate(Req :: map()) -> {ok, Result :: term(), Cookies :: cookies() } | {error, {csrf_verification_failed, cookies()}} | {error, term()}.
```
Where:

* `Req` is a request coming from `cowboy`

The possible returns are:
* `{ok, Result :: term(), Cookies:: cookies()}` - When the authentication is successfull. `Result` may contain an arbitrary data that will then be passed in the `auth_data` key of the request. See [Request section](#request) for details. Cookies are a list of key value pairs of strings.
* `{error, {csrf_verification_failed, cookies()}}` - Special error clause for CSRF validation that authentication may provide. This will cause a 403 error to be returned to the client together with any cookies that the error can contain.
* `{error, term()}` - Any other authentication error. In this case the request will still be forwarded towards AMQP, but `auth_data` will be empty.

## Clients
Currently no client-side libraries for `broen` are available, but creating your own client is very easy, using just an AMQP library.

The client must simply connect to the RabbitMQ broker and create bind its queue to the `http_exchange` with the routing key representing the URL it is to handle and then follow the same serialization protocol as configured for `broen`

For example, a `broen` client written using Erlang may make use of [amqp_director](https://hex.pm/packages/amqp_director) and do the following:

```erlang

start(ConnInfo) ->
  Url = start_server(ConnInfo, "routing_test.working", fun working_key/3),
  {ok, {Resp, Props, Payload}} = httpc:request(get, {Url, []}, [], []),
  {_, 200, _} = Resp,
  "application/json" = proplists:get_value("content-type", Props),
  #{<<"message">> := <<"Hello!">>} = jsx:decode(list_to_binary(Payload), [return_maps])

working_key(Payload, <<"application/json">>, _Type) ->
  Unpacked = jsx:decode(Payload, [return_maps]),
  <<"GET">> = maps:get(<<"method">>, Unpacked),
  {reply, jsx:encode(#{
                       media_type => <<"application/json">>,
                       payload => jsx:encode(#{message => <<"Hello!">>})
                     }), <<"application/json">>}.

start_server(ConnInfo, RoutingKey, Handler) ->
  {ok, Hostname} = inet:gethostname(),
  UrlBit = lists:flatten(string:replace(RoutingKey, ".", "/", all)),
  QueueName = iolist_to_binary([RoutingKey, "-", Hostname]),
  WorkingUrl = "http://localhost:7083/call/" ++ UrlBit,

  AmqpConfig = [{exchange, <<"http_exchange">>},
                {consume_queue, QueueName},
                no_ack,
                {queue_definitions, [#'exchange.declare'{exchange = <<"http_exchange">>,
                                                         type     = <<"topic">>},
                                     #'queue.declare'{queue       = QueueName,
                                                      exclusive   = true,
                                                      auto_delete = true
                                     },
                                     #'queue.bind'{exchange    = <<"http_exchange">>,
                                                   queue       = QueueName,
                                                   routing_key = iolist_to_binary([RoutingKey, ".#"])}
                ]}],
  {ok, Pid} = amqp_server_sup:start_link(list_to_atom(RoutingKey ++ "_test"), ConnInfo, AmqpConfig, Handler, 1),
  unlink(Pid),
  WorkingUrl.
```

More examples can be found in the tests for `broen`.


## Migrating to 2.0
The only difference in 2.0 is that `broen` no longer uses Yaws, switching instead to `cowboy`. That means `yaws` configuration is no longer relevant.

Additionally, `cors_allowed_origins` option in `sys.config` must now be binary strings.
