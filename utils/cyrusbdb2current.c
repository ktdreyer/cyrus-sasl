#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <sasl.h>
#include <saslplug.h>
#include "../sasldb/sasldb.h"

/* Cheating to make the utils work out right */
extern const sasl_utils_t *sasl_global_utils;
sasl_conn_t *globalconn;

typedef void *listcb_t(const char *, const char *, const char *,
		       const char *, unsigned);

void listusers_cb(const char *authid, const char *realm,
		  const char *propName, const char *secret,
		  unsigned seclen)
{
    if (!authid || !propName || !realm) {
	fprintf(stderr,"userlist callback has bad param");
	return;
    }

    /* the entries that just say the mechanism exists */
    if (strlen(authid)==0) return;

    printf("Converting: %s@%s (%s)...",authid,realm,propName);

    _sasldb_putdata(sasl_global_utils, globalconn,
		    authid, realm, propName,
		    secret, seclen);

    printf("ok\n");
}

/*
 * List all users in database
 */

#include <db.h>

#define DB_VERSION_FULL ((DB_VERSION_MAJOR << 24) | (DB_VERSION_MINOR << 16) | DB_VERSION_PATCH)
/*
 * Open the database
 *
 */
static int berkeleydb_open(const char *path,DB **mbdb)
{
    int ret;

#if DB_VERSION_FULL < 0x03000000
    ret = db_open(path, DB_HASH, DB_CREATE, 0664, NULL, NULL, mbdb);
#else /* DB_VERSION_FULL < 0x03000000 */
    ret = db_create(mbdb, NULL, 0);
    if (ret == 0 && *mbdb != NULL)
    {
#if DB_VERSION_FULL >= 0x04010000
	ret = (*mbdb)->open(*mbdb, NULL, path, NULL, DB_HASH, DB_CREATE, 0664);
#else
	ret = (*mbdb)->open(*mbdb, path, NULL, DB_HASH, DB_CREATE, 0664);
#endif
	if (ret != 0)
	{
	    (void) (*mbdb)->close(*mbdb, 0);
	    *mbdb = NULL;
	}
    }
#endif /* DB_VERSION_FULL < 0x03000000 */

    if (ret != 0) {
	fprintf(stderr,"Error opening password file %s\n", path);
	return SASL_FAIL;
    }

    return SASL_OK;
}

/*
 * Close the database
 *
 */

static void berkeleydb_close(DB *mbdb)
{
    int ret;
    
    ret = mbdb->close(mbdb, 0);
    if (ret!=0) {
	fprintf(stderr,"error closing sasldb: %s",
		db_strerror(ret));
    }
}

int listusers(const char *path, listcb_t *cb)
{
    int result;
    DB *mbdb = NULL;
    DBC *cursor;
    DBT key, data;

    /* open the db */
    result=berkeleydb_open(path, &mbdb);
    if (result!=SASL_OK) goto cleanup;

    /* make cursor */
#if DB_VERSION_FULL < 0x03060000
    result = mbdb->cursor(mbdb, NULL,&cursor); 
#else
    result = mbdb->cursor(mbdb, NULL,&cursor, 0); 
#endif /* DB_VERSION_FULL < 0x03060000 */

    if (result!=0) {
	fprintf(stderr,"Making cursor failure: %s\n",db_strerror(result));
      result = SASL_FAIL;
      goto cleanup;
    }

    memset(&key,0, sizeof(key));
    memset(&data,0,sizeof(data));

    /* loop thru */
    result = cursor->c_get(cursor, &key, &data,
			   DB_FIRST);

    while (result != DB_NOTFOUND)
    {
	char *authid;
	char *realm;
	char *tmp;
	unsigned int len;
	char prop[1024];
	int numnulls = 0;
	unsigned int lup;

	/* make sure there are exactly 2 null's */
	for (lup=0;lup<key.size;lup++)
	    if (((char *)key.data)[lup]=='\0')
		numnulls++;

	if (numnulls != 2) {
	    fprintf(stderr,"warning: probable database corruption\n");
	    result = cursor->c_get(cursor, &key, &data, DB_NEXT);
	    continue;
	}

	authid = key.data;
	realm  = authid + strlen(authid)+1;
	tmp    = realm + strlen(realm)+1;
	len = key.size - (tmp - authid);

	/* make sure we have enough space of prop */
	if (len >=sizeof(prop)) {
	    fprintf(stderr,"warning: absurdly long prop name\n");
	    result = cursor->c_get(cursor, &key, &data, DB_NEXT);
	    continue;
	}

	memcpy(prop, tmp, key.size - (tmp - ((char *)key.data)));
	prop[key.size - (tmp - ((char *)key.data))] = '\0';

	if (*authid) {
	    /* don't check return values */
	    cb(authid,realm,prop,data.data,data.size);
	}

	result = cursor->c_get(cursor, &key, &data, DB_NEXT);
    }

    if (result != DB_NOTFOUND) {
	fprintf(stderr,"failure: %s\n",db_strerror(result));
	result = SASL_FAIL;
	goto cleanup;
    }

    result = cursor->c_close(cursor);
    if (result != 0) {
        result = SASL_FAIL;
        goto cleanup;
    }

    result = SASL_OK;

 cleanup:

    if (mbdb != NULL) berkeleydb_close(mbdb);
    return result;
}


char *db = NULL, *db_new=NULL;

int good_getopt(void *context __attribute__((unused)), 
		const char *plugin_name __attribute__((unused)), 
		const char *option,
		const char **result,
		unsigned *len)
{
    if (db_new && !strcmp(option, "sasldb_path")) {
	*result = db_new;
	if (len)
	    *len = strlen(db_new);
	return SASL_OK;
    }

    return SASL_FAIL;
}

static struct sasl_callback goodsasl_cb[] = {
    { SASL_CB_GETOPT, (int (*)(void))&good_getopt, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int main(int argc, char **argv)
{
    int result;
    FILE *f;

    if (argc != 3) {
	fprintf(stderr, "Usage: cyrusbdb2current old_sasldb new_sasldb\n");
	fprintf(stderr, "old_sasldb is presumably /etc/sasldb2\n");
       	fprintf(stderr, "new_sasldb is presumably /etc/sasl2/sasldb2\n");
	return 1;
    }

    db = argv[1];
    db_new = argv[2];

    if (strcmp(db, db_new) == 0) {
	fprintf(stderr, "Old and new files should be different\n");
	return 1;
    }


    f = fopen(db_new, "rb");
    if (f != NULL) {
	fprintf(stderr, "The specified target file %s already exists\n", db_new);
	fclose(f);
	return 1;
    }

    result = sasl_server_init(goodsasl_cb, "dbconverter");
    if (result != SASL_OK) {
	fprintf(stderr, "couldn't init saslv2\n");
	return 1;
    }

    result = sasl_server_new("sasldb",
			     "localhost",
			     NULL,
			     NULL,
			     NULL,
			     NULL,
			     0,
			     &globalconn);
    if (result != SASL_OK) {
	fprintf(stderr, "couldn't create globalconn\n");
	return 1;
    }

    if(_sasl_check_db(sasl_global_utils,globalconn) != SASL_OK) {
	fprintf(stderr, "target DB %s is not OK\n", db_new);
	return 1;
    }

    printf("\nThis program will take the sasldb file specified on the\n"
           "command line and convert it to a new sasldb specified\n"
           "on the command line. It is STRONGLY RECOMMENDED that you\n"
           "backup sasldb before allowing this program to run\n\n"
	   "We are going to convert %s and our output will be in %s\n\n"
           "Press return to continue\n", db, db_new);

    getchar();

    listusers(db, (listcb_t *) &listusers_cb);

    sasl_dispose(&globalconn);
    sasl_done();

    exit(0);
}
