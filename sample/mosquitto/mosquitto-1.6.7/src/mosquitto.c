#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <grp.h>
#include <assert.h>

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "util_mosq.h"
#include "packet_mosq.h"
#include "mqtt_protocol.h"
#include "alias_mosq.h"

#include "mosquitto_internal.h"

#define on_error(...)             \
  {                               \
    fprintf(stderr, __VA_ARGS__); \
    fflush(stderr);               \
    exit(1);                      \
  }

struct mosquitto_db int_db;

bool flag_reload = false;
#ifdef WITH_PERSISTENCE
bool flag_db_backup = false;
#endif
bool flag_tree_print = false;
int run;
#ifdef WITH_WRAP
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;
#endif

void handle_sigint(int signal);
void handle_sigusr1(int signal);
void handle_sigusr2(int signal);
#ifdef SIGHUP
void handle_sighup(int signal);
#endif

struct mosquitto_db *mosquitto__get_db(void)
{
	return &int_db;
}

/* mosquitto shouldn't run as root.
 * This function will attempt to change to an unprivileged user and group if
 * running as root. The user is given in config->user.
 * Returns 1 on failure (unknown user, setuid/setgid failure)
 * Returns 0 on success.
 * Note that setting config->user to "root" does not produce an error, but it
 * strongly discouraged.
 */
int drop_privileges(struct mosquitto__config *config, bool temporary)
{
#if !defined(__CYGWIN__) && !defined(WIN32)
	struct passwd *pwd;
	char *err;
	int rc;

	const char *snap = getenv("SNAP_NAME");
	if(snap && !strcmp(snap, "mosquitto")){
		/* Don't attempt to drop privileges if running as a snap */
		return MOSQ_ERR_SUCCESS;
	}

	if(geteuid() == 0){
		if(config->user && strcmp(config->user, "root")){
			pwd = getpwnam(config->user);
			if(!pwd){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid user '%s'.", config->user);
				return 1;
			}
			if(initgroups(config->user, pwd->pw_gid) == -1){
				err = strerror(errno);
				log__printf(NULL, MOSQ_LOG_ERR, "Error setting groups whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = setegid(pwd->pw_gid);
			}else{
				rc = setgid(pwd->pw_gid);
			}
			if(rc == -1){
				err = strerror(errno);
				log__printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = seteuid(pwd->pw_uid);
			}else{
				rc = setuid(pwd->pw_uid);
			}
			if(rc == -1){
				err = strerror(errno);
				log__printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst dropping privileges: %s.", err);
				return 1;
			}
		}
		if(geteuid() == 0 || getegid() == 0){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Mosquitto should not be run as root/administrator.");
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}

int restore_privileges(void)
{
#if !defined(__CYGWIN__) && !defined(WIN32)
	char *err;
	int rc;

	if(getuid() == 0){
		rc = setegid(0);
		if(rc == -1){
			err = strerror(errno);
			log__printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst restoring privileges: %s.", err);
			return 1;
		}
		rc = seteuid(0);
		if(rc == -1){
			err = strerror(errno);
			log__printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst restoring privileges: %s.", err);
			return 1;
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


void mosquitto__daemonise(void)
{
#ifndef WIN32
	char *err;
	pid_t pid;

	pid = fork();
	if(pid < 0){
		err = strerror(errno);
		log__printf(NULL, MOSQ_LOG_ERR, "Error in fork: %s", err);
		exit(1);
	}
	if(pid > 0){
		exit(0);
	}
	if(setsid() < 0){
		err = strerror(errno);
		log__printf(NULL, MOSQ_LOG_ERR, "Error in setsid: %s", err);
		exit(1);
	}

	assert(freopen("/dev/null", "r", stdin));
	assert(freopen("/dev/null", "w", stdout));
	assert(freopen("/dev/null", "w", stderr));
#else
	log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Can't start in daemon mode in Windows.");
#endif
}

int mqtt_process(struct mosquitto *context)
{
	uint8_t byte;
	ssize_t read_length;

	if (context->in_packet.command == 0) {
		read_length = recv(context->sock, &byte, 1, 0);
		if (read_length == 1) {
			context->in_packet.command = byte;
			if (getenv("DEBUG_MODE"))
				printf("[ server ] Received command: 0x%x\n", byte);
		} else {
			if (getenv("DEBUG_MODE"))
				printf("[ server ] Receive command failed due to (%d): %s\n", errno, strerror(errno));
			return 0;
		}
	}

	if (context->in_packet.remaining_count <= 0) {
		do {
			read_length = recv(context->sock, &byte, 1, 0);
			if (read_length == 1) {
				context->in_packet.remaining_count--;
				if(context->in_packet.remaining_count < -4){
					if (getenv("DEBUG_MODE"))
						printf("[ server ] Error in protocol\n");
					return 0;
				}

				context->in_packet.remaining_length += (byte & 127) * context->in_packet.remaining_mult;
				context->in_packet.remaining_mult *= 128;
			} else {
				if (getenv("DEBUG_MODE"))
					printf("[ server ] Receive remain failed due to (%d): %s\n", errno, strerror(errno));
				return 0;
			}
		} while ((byte & 128) != 0);
		context->in_packet.remaining_count *= -1;

		if (context->in_packet.remaining_length > 0) {
			context->in_packet.payload = mosquitto__malloc(context->in_packet.remaining_length*sizeof(uint8_t));
			if(!context->in_packet.payload){
				if (getenv("DEBUG_MODE"))
					printf("[ server ] Mosquitto malloc(%lu) failed due to (%d): %s\n",(size_t)(context->in_packet.remaining_length*sizeof(uint8_t)), errno, strerror(errno));
				
				return 0;
			}
			context->in_packet.to_process = context->in_packet.remaining_length;
		}
	}

	while (context->in_packet.to_process > 0) {
		read_length = recv(context->sock, &(context->in_packet.payload[context->in_packet.pos]), context->in_packet.to_process, 0);
		if (read_length > 0) {
			context->in_packet.to_process -= read_length;
			context->in_packet.pos += read_length;
		} else {
			if (getenv("DEBUG_MODE"))
				printf("[ server ] Receive payload failed due to (%d): %s\n", errno, strerror(errno));
			return 0;
		}
	}

	context->in_packet.pos = 0;
	if ((context->in_packet.command&0xF0) != CMD_DISCONNECT)
		handle__packet(&int_db, context);
	packet__cleanup(&context->in_packet);
	return 1;
}

struct mosquitto *init_context(struct mosquitto_db* db, int sock)
{
	struct mosquitto *context;

	context = mosquitto__calloc(1, sizeof(struct mosquitto));
	if(!context) return NULL;
	
	context->pollfd_index = -1;
	mosquitto__set_state(context, mosq_cs_new);
	context->sock = sock;
	context->last_msg_in = 0;
	context->next_msg_out = 60;
	context->keepalive = 60; /* Default to 60s */
	context->clean_start = true;
	context->id = NULL;
	context->last_mid = 0;
	context->will = NULL;
	context->username = NULL;
	context->password = NULL;
	context->listener = NULL;
	context->acl_list = NULL;

	/* is_bridge records whether this client is a bridge or not. This could be
	 * done by looking at context->bridge for bridges that we create ourself,
	 * but incoming bridges need some other way of being recorded. */
	context->is_bridge = false;

	context->in_packet.payload = NULL;
	packet__cleanup(&context->in_packet);
	context->out_packet = NULL;
	context->current_out_packet = NULL;

	context->address = mosquitto__strdup("127.0.0.1");
	
	context->bridge = NULL;
	context->msgs_in.inflight_maximum = 20;
	context->msgs_out.inflight_maximum = 20;
	context->msgs_in.inflight_quota = 20;
	context->msgs_out.inflight_quota = 20;
	context->maximum_qos = 2;

	if (getenv("DEBUG_MODE"))
		printf("[ server ] Before add hash\n");
	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);
	if (getenv("DEBUG_MODE"))
		printf("[ server ] After add hash\n");

	return context;
}

void clear_context(struct mosquitto_db* db, struct mosquitto *context)
{
	int do_free = 1;
	struct mosquitto__packet *packet;

	HASH_DELETE(hh_sock, db->contexts_by_sock, context);
	alias__free_all(context);

	mosquitto__free(context->auth_method);
	context->auth_method = NULL;

	mosquitto__free(context->username);
	context->username = NULL;

	mosquitto__free(context->password);
	context->password = NULL;

	if(do_free || context->clean_start){
		sub__clean_session(db, context);
		db__messages_delete(db, context);
	}

	mosquitto__free(context->address);
	context->address = NULL;

	context__send_will(db, context);

	if(context->id){
		context__remove_from_by_id(db, context);
		mosquitto__free(context->id);
		context->id = NULL;
	}
	packet__cleanup(&(context->in_packet));
	if(context->current_out_packet){
		packet__cleanup(context->current_out_packet);
		mosquitto__free(context->current_out_packet);
		context->current_out_packet = NULL;
	}
	while(context->out_packet){
		packet__cleanup(context->out_packet);
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		mosquitto__free(packet);
	}
	if(do_free || context->clean_start){
		db__messages_delete(db, context);
	}

	if(do_free){
		mosquitto__free(context);
	}
}

int main(int argc, char *argv[])
{
	struct mosquitto__config config;

	memset(&int_db, 0, sizeof(struct mosquitto_db));
	config__init(&int_db, &config);
	config__parse_args(&int_db, &config, argc, argv);
	int_db.config = &config;
	db__open(&config, &int_db);
	mosquitto_security_module_init(&int_db);
	mosquitto_security_init(&int_db, false);

	int server_fd, client_fd, err;
	struct sockaddr_in server, client;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0)
		on_error("Could not create socket due to (%d): %s\n", errno, strerror(errno));

	server.sin_family = AF_INET;
	server.sin_port = htons(1337);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	err = bind(server_fd, (struct sockaddr *)&server, sizeof(server));
	if (err < 0)
		on_error("Could not bind socket due to (%d): %s\n", errno, strerror(errno));

	err = listen(server_fd, 128);
	if (err < 0)
		on_error("Could not listen on socket due to (%d): %s\n", errno, strerror(errno));

	printf("Server is listening on 1337\n");

	while (1) {
		socklen_t client_len = sizeof(client);
		client_fd = accept(server_fd, (struct sockaddr *)&client, &client_len);
	
		if (client_fd < 0)
			on_error("Could not establish new connection due to (%d): %s\n", errno, strerror(errno));

		printf("[ server ] Client connected!\n");
		
		struct mosquitto *context = init_context(&int_db, client_fd);

		if (getenv("DEBUG_MODE"))
			printf("[ server ] +++ Start process data\n");
		while (mqtt_process(context));
		if (getenv("DEBUG_MODE"))
			printf("[ server ] --- Done process data\n");

		clear_context(&int_db, context);

		close(client_fd);
	}

	return 0;
}