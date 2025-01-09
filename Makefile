REBAR=rebar3
CONFIG_FILE ?= test/sys-test.config


### Local building
##################################
build:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

distclean: clean
	rm -rf _build

### Local testing
##################################
test: test-eunit test-ct

test-eunit:
	$(REBAR) eunit

test-ct:
	$(REBAR) ct --readable=false --sys_config=$(CONFIG_FILE)
dialyzer:
	$(REBAR) dialyzer

publish:
	$(REBAR) hex publish


### Docker
##################################

DOCKER_DEV_COMPOSE := docker compose --file docker/dev-compose.yml --project-name broen

dev-console:
	$(DOCKER_DEV_COMPOSE) up --remove-orphans --detach --wait
	$(DOCKER_DEV_COMPOSE) exec --workdir /app broen-dev /bin/bash
