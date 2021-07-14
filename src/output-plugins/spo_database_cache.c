/*
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
 *    Theses caches are built by combining existing caches from the snort map files and config files,
 *    The goal is to reduce the number of database interaction to a minimum so the output plugins 
 *    is more performant especially under heavy load of events.
 *
 *   
 *    Note that the default schema compatibility is kept intact
 *    Maintainers : The Barnyard2 Team <firnsy@gmail.com> <beenph@gmail.com> - 2011-2012
 *
 *    Special thanks to: Rusell Fuleton <russell.fulton@gmail.com> for helping us stress test
 *                       this in production for us.
 *
 */

#include "output-plugins/spo_database.h"
#include "output-plugins/spo_database_cache.h"


/* LOOKUP FUNCTIONS */
cacheSignatureObj *cacheGetSignatureNodeUsingDBid(cacheSignatureObj *iHead,u_int32_t lookupId);
cacheReferenceObj *cacheGetReferenceNodeUsingDBid(cacheSystemObj *iHead,u_int32_t lookupId);

u_int32_t cacheSignatureLookup(dbSignatureObj *iLookup,cacheSignatureObj *iHead);
u_int32_t cacheClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead);
u_int32_t cacheSystemLookup(dbSystemObj *iLookup,cacheSystemObj *iHead,cacheSystemObj **rcacheSystemObj);
u_int32_t cacheReferenceLookup(dbReferenceObj *iLookup,cacheReferenceObj *iHead,cacheReferenceObj **retRefLookupNode);

u_int32_t dbSignatureReferenceLookup(dbSignatureReferenceObj *iLookup,cacheSignatureReferenceObj *iHead,cacheSignatureReferenceObj **retSigRef,u_int32_t refCondCheck);
u_int32_t dbReferenceLookup(dbReferenceObj *iLookup,cacheReferenceObj *iHead);
u_int32_t dbSystemLookup(dbSystemObj *iLookup,cacheSystemObj *iHead);
u_int32_t dbSignatureLookup(dbSignatureObj *iLookup,cacheSignatureObj *iHead);
u_int32_t dbClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead);
/* LOOKUP FUNCTIONS */


/* CLASSIFICATION FUNCTIONS */
u_int32_t ClassificationPullDataStore(DatabaseData *data, dbClassificationObj **iArrayPtr,u_int32_t *array_length);
u_int32_t ClassificationCacheUpdateDBid(dbClassificationObj *iDBList,u_int32_t array_length,cacheClassificationObj **cacheHead);
u_int32_t ClassificationPopulateDatabase(DatabaseData  *data,cacheClassificationObj *cacheHead);
u_int32_t ClassificationCacheSynchronize(DatabaseData *data,cacheClassificationObj **cacheHead);
/* CLASSIFICATION FUNCTIONS */

/* SIGNATURE FUNCTIONS */
u_int32_t SignaturePopulateDatabase(DatabaseData  *data,cacheSignatureObj *cacheHead,int inTransac);
u_int32_t SignatureCacheUpdateDBid(dbSignatureObj *iDBList,u_int32_t array_length,cacheSignatureObj **cacheHead);
u_int32_t SignaturePullDataStore(DatabaseData *data, dbSignatureObj **iArrayPtr,u_int32_t *array_length);
u_int32_t SignatureCacheSynchronize(DatabaseData *data,cacheSignatureObj **cacheHead);
/* SIGNATURE FUNCTIONS */

/* REFERENCE FUNCTIONS */
u_int32_t ReferencePullDataStore(DatabaseData *data, dbReferenceObj **iArrayPtr,u_int32_t *array_length);
u_int32_t ReferenceCacheUpdateDBid(dbReferenceObj *iDBList,u_int32_t array_length,cacheSystemObj **cacheHead);
u_int32_t ReferencePopulateDatabase(DatabaseData  *data,cacheReferenceObj *cacheHead);
/* REFERENCE FUNCTIONS */

/* SYSTEM FUNCTIONS */
u_int32_t SystemPopulateDatabase(DatabaseData  *data,cacheSystemObj *cacheHead);
u_int32_t SystemPullDataStore(DatabaseData *data, dbSystemObj **iArrayPtr,u_int32_t *array_length);
u_int32_t SystemCacheUpdateDBid(dbSystemObj *iDBList,u_int32_t array_length,cacheSystemObj **cacheHead);
u_int32_t SystemCacheSynchronize(DatabaseData *data,cacheSystemObj **cacheHead);
/* SYSTEM FUNCTIONS */


/* SIGNATURE REFERENCE FUNCTIONS */
u_int32_t SignatureReferencePullDataStore(DatabaseData *data, dbSignatureReferenceObj **iArrayPtr,u_int32_t *array_length);
u_int32_t SignatureReferenceCacheUpdateDBid(dbSignatureReferenceObj *iDBList,
					    u_int32_t array_length,
					    cacheSignatureReferenceObj **cacheHead,
					    cacheSignatureObj *sigCacheHead,
					    cacheSystemObj *systemCacheHead);

u_int32_t SignatureReferencePopulateDatabase(DatabaseData *data,cacheSignatureReferenceObj *cacheHead);
u_int32_t SigRefSynchronize(DatabaseData *data,cacheSignatureReferenceObj **cacheHead,cacheSignatureObj *cacheSigHead);
u_int32_t SignatureReferencePreGenerate(cacheSignatureObj *iHead);
/* SIGNATURE REFERENCE FUNCTIONS */


/* Init FUNCTIONS */
u_int32_t ConvertDefaultCache(Barnyard2Config *bc,DatabaseData *data);
u_int32_t GenerateSigRef(cacheSignatureReferenceObj **iHead,cacheSignatureObj *sigHead);
u_int32_t ConvertReferenceCache(ReferenceNode *iHead,MasterCache *iMasterCache,cacheSignatureObj *cSobj,DatabaseData *data);
u_int32_t ConvertClassificationCache(ClassType **iHead, MasterCache *iMasterCache,DatabaseData *data);
u_int32_t ConvertSignatureCache(SigNode **iHead,MasterCache *iMasterCache,DatabaseData *data);
u_int32_t CacheSynchronize(DatabaseData *data);
/* Init FUNCTIONS */


/* Destructor */
void MasterCacheFlush(DatabaseData *data,u_int32_t flushFlag);
/* Destructor */

/* Return largest string lenght */
inline u_int32_t glsl(char *a,char *b)
{
    u_int32_t alen = 0;
    u_int32_t blen = 0;
    
    alen = strlen(a);
    blen = strlen(b);
    
    if(alen > blen)
    {
	return alen;
    }
    else if(alen < blen)
    {
	return blen;
    }
    if(alen == blen)
    {
	return alen;
    }

    abort();
    return 0;
}

#if DEBUG
u_int32_t file_reference_object_count = 0;
u_int32_t file_system_object_count = 0;
u_int32_t file_signature_object_count = 0;
u_int32_t file_classification_object_count = 0;
u_int32_t file_sigref_object_count = 0;

u_int32_t db_reference_object_count = 0;
u_int32_t db_system_object_count = 0;
u_int32_t db_signature_object_count = 0;
u_int32_t db_classification_object_count = 0;
u_int32_t db_sigref_object_count = 0;

u_int32_t inserted_reference_object_count = 0;
u_int32_t inserted_system_object_count = 0;
u_int32_t inserted_signature_object_count = 0;
u_int32_t inserted_classification_object_count = 0;
u_int32_t inserted_sigref_object_count = 0;
#endif



/** 
 * Lookup for dbSignatureReferenceObj in cacheSignatureReferenceObj 
 *
 * @note ref_seq is not compared because it could have changed and it is 
 *       handled elsewhere.
 *
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t cacheSignatureReferenceLookup(dbSignatureReferenceObj *iLookup,cacheSignatureReferenceObj *iHead)
{
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbReferenceSignatureObj[0x%x] cacheSignatureReferenceObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
    
    while(iHead != NULL)
    {
	if( ((iLookup->db_ref_id == iHead->obj.db_ref_id) &&
	     (iLookup->db_sig_id == iHead->obj.db_sig_id)))
	{
	    /* Found */
	    return 1;
        }
        iHead = iHead->next;
    }
    return 0;
}


u_int32_t cacheEventSignatureLookup(cacheSignatureObj *iHead,
				    plgSignatureObj *sigContainer,
				    u_int32_t gid,
				    u_int32_t sid)
{
    u_int32_t matchCount = 0;
    
    if( (iHead == NULL) ||
	(sigContainer == NULL))
    {
	return 0;
    }
    
    /* Clean up */
    memset(sigContainer,'\0',(sizeof(plgSignatureObj) * MAX_SIGLOOKUP));
    
    while(iHead != NULL)
    {
	if( (iHead->obj.sid == sid) &&
	    (iHead->obj.gid == gid))
	{
	    if(matchCount < MAX_SIGLOOKUP)
	    {
		sigContainer[matchCount].cacheSigObj = iHead;
		matchCount++;
	    }
	    else
	    {
		/* We reached maximum count for possible reference matching objects... */
		return matchCount;
	    }
	}
	
	iHead = iHead->next;
    }
    
    return matchCount;
}



/** 
 * Lookup for dbSignatureObj in cacheReferenceObj 
 * @note compare message,sid,gid and revision.
 *
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t cacheSignatureLookup(dbSignatureObj *iLookup,cacheSignatureObj *iHead)
{
    
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbSignatureObj[0x%x] cacheSignatureObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }

    while(iHead != NULL)
    {
	
	if( (strncasecmp(iLookup->message,iHead->obj.message,
			 glsl(iLookup->message,iHead->obj.message)) == 0) &&
            (iLookup->sid == iHead->obj.sid) &&
            (iLookup->gid == iHead->obj.gid) &&
            (iLookup->rev == iHead->obj.rev))
        {
            /* Found */
            return 1;
        }
	
        iHead = iHead->next;
    }

    return 0;
    
}


/**
 * Lookup for dbSignatureObj in cacheReferenceObj and if a match is found it will return the object for further comparaisons.
 * @note compare message,sid,gid and revision.
 *
 * @param iLookup
 * @param iHead
 *
 * @return
 * NULL           NOT FOUND
 * Valid POINTER  FOUND
 */
cacheSignatureObj * cacheSignatureGetObject(dbSignatureObj *iLookup,cacheSignatureObj *iHead)
{

    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbSignatureObj[0x%x] cacheSignatureObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }

    while(iHead != NULL)
    {
	if( (strncasecmp(iLookup->message,iHead->obj.message,
			 glsl(iLookup->message,iHead->obj.message)) == 0) &&
            (iLookup->sid == iHead->obj.sid) &&
            (iLookup->gid == iHead->obj.gid) &&
            (iLookup->rev == iHead->obj.rev))
        {
            /* Found */
            return iHead;
        }
	
        iHead = iHead->next;
    }

    return NULL;
}

u_int32_t cacheEventClassificationLookup(cacheClassificationObj *iHead,u_int32_t iClass_id)
{
    
    if(iHead == NULL)
    {
	return 0;
    }
    
    while(iHead != NULL)
    {
	if(iHead->obj.sig_class_id == iClass_id)
	{
	    return iHead->obj.db_sig_class_id;
	}
	
	iHead = iHead->next;
    }
    
    return 0;
}

/** 
 * Lookup for dbClassificationObj in cacheClassificationObj 
 * 
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t cacheClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead)
{
    if( (iLookup == NULL))
    {
	/* XXX */
        FatalError("database [%s()], Called with dbClassiciationObj[0x%x] cacheClassificationObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
	
    if(iHead == NULL) 
    {
	return 0;
    }
    
    while(iHead != NULL)
    {
	if( (memcmp(iLookup,&iHead->obj,sizeof(dbClassificationObj)) == 0))
	{
	    /* Found */
	    return 1;
	}
	
	iHead = iHead->next;
    }
    
    return 0;
}

/** 
 * Lookup for dbSystemObj in cacheSystemObj and also set rcacheSystemObj to found object.
 * 
 * @param iLookup 
 * @param iHead 
 * @param rcacheSystemObj 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t cacheSystemLookup(dbSystemObj *iLookup,cacheSystemObj *iHead,cacheSystemObj **rcacheSystemObj)
{
    
    if( (iLookup == NULL) ||
	(rcacheSystemObj == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbReferenceObj[0x%x] cacheReferenceObj[0x%x] **rcacheSystemObj[0x%x]\n",
                   __FUNCTION__,
                   iLookup,
                   iHead,
	           rcacheSystemObj);
    }
    
    while(iHead != NULL)
    {
        if( (memcmp(iLookup->ref_system_name,iHead->obj.ref_system_name,SYSTEM_NAME_LEN) == 0) &&
	    (memcmp(iLookup->ref_system_url,iHead->obj.ref_system_url,SYSTEM_URL_LEN) == 0))
	{
            /* Match */
	    *rcacheSystemObj = iHead;
            return 1;
        }

        iHead = iHead->next;
    }

    return 0;
}


/** 
  * Lookup for dbReferenceObj in cacheReferenceObj and also set retRefLookupNode found object.
 * 
 * @param iLookup 
 * @param iHead 
 * @param retRefLookupNode 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t cacheReferenceLookup(dbReferenceObj *iLookup,cacheReferenceObj *iHead,cacheReferenceObj **retRefLookupNode)
{
    if( (iLookup == NULL) ||
	(retRefLookupNode == NULL))
    {
	/* XXX */
	FatalError("database [%s()], Called with dbReferenceObj[0x%x] cacheReferenceObj[0x%x] \n",
		   __FUNCTION__,
		   iLookup,
		   iHead);
    }
    
    while(iHead != NULL)
    {
	if( (strncasecmp(iLookup->ref_tag,iHead->obj.ref_tag,
			 glsl(iLookup->ref_tag,iHead->obj.ref_tag)) == 0))
	{
	    /* Match */
	    *retRefLookupNode = iHead;
	    return 1;
	}
	
        iHead = iHead->next;
    }
    
    return 0;
} 

/** 
 * Lookup for dbSignatureReferenceObj in cacheSignatureReferenceObj 
 * and return the cacheSignatureReferenceObj found (if any)
 * @note ref_seq is not compared because it could have changed and it is 
 *       handled elsewhere.
 *
 * @param iLookup 
 * @param iHead 
 * @param retSigRef 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t dbSignatureReferenceLookup(dbSignatureReferenceObj *iLookup,cacheSignatureReferenceObj *iHead,cacheSignatureReferenceObj **retSigRef,u_int32_t refCondCheck)
 {
     
     if( (iLookup == NULL) ||
	 (retSigRef == NULL))
     {
	 /* XXX */
	 FatalError("database [%s()], Called with dbReferenceSignatureObj[0x%x] cacheSignatureReferenceObj [0x%x] \n",
                   __FUNCTION__,
		    iLookup,
		    iHead);
     }
     
     while(iHead != NULL)
     {
	 
	 if(refCondCheck == 0)
	 {
	     if( (iLookup->ref_seq == iHead->obj.ref_seq) &&
		 (iLookup->db_sig_id == iHead->obj.db_sig_id))
	     {
		 /* Found */
		 *retSigRef = iHead;
		 return 1;
	     }
	 }
	 else if(refCondCheck == 1)
	 {
	     if( (iLookup->db_ref_id == iHead->obj.db_ref_id) &&
                 (iLookup->db_sig_id == iHead->obj.db_sig_id))
             {
		 /* Found */
                 *retSigRef = iHead;
                 return 1;
             }

	 }

	     
	 

	 iHead = iHead->next;
     }
     
     return 0;
 }


/** 
 * Lookup for dbReferenceObj in cacheReferenceObj 
 * @note Only compare tag, from there assign system_id from parent node
 *       and reference id from lookup id.
 * @note Used in context db->internaCache lookup (if found remove CACHE_INTERNAL_ONLY and set CACHE_BOTH flag)
 *
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t dbReferenceLookup(dbReferenceObj *iLookup,cacheReferenceObj *iHead)
{
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbReferenceObj[0x%x] cacheReferenceObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
    
    if(iHead == NULL)
    {
        return 0;
    }
    
    while(iHead != NULL)
    {
	if( (strncasecmp(iLookup->ref_tag,iHead->obj.ref_tag,
			 glsl(iLookup->ref_tag,iHead->obj.ref_tag))) == 0)
	{
            /* Found */
	    if(iHead->flag & CACHE_INTERNAL_ONLY)
	    {
		iHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
	    }
	    else
	    {
		iHead->flag ^= CACHE_BOTH;
	    }
	    
	    iHead->obj.ref_id = iLookup->ref_id;
	    iHead->obj.system_id = iHead->obj.parent->obj.db_ref_system_id;
	    return 1;
	}
        iHead = iHead->next;
    }
    
    return 0;
}

/** 
 * Lookup for dbSystemObj in cacheSystemeObj 
 * @note compare only reference name, assign system id from parent node if a match is found.
 * @note Used in context db->internaCache lookup (if found remove CACHE_INTERNAL_ONLY and set CACHE_BOTH flag)
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t dbSystemLookup(dbSystemObj *iLookup,cacheSystemObj *iHead)
{
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbSystemObj[0x%x] cacheSystemObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
    
    if(iHead == NULL)
    {
        return 0;
    }
    
    while(iHead != NULL)
    {
	if((strncasecmp(iLookup->ref_system_name,iHead->obj.ref_system_name, 
			glsl(iLookup->ref_system_name,iHead->obj.ref_system_name))) == 0)
	{
            /* Found */
	    if(  iHead->flag & CACHE_INTERNAL_ONLY)
	    {
		iHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
	    }
	    else
	    {
		iHead->flag ^= CACHE_BOTH;
	    }

	    iHead->obj.db_ref_system_id = iLookup->db_ref_system_id;
            return 1;
        }
	
	iHead = iHead->next;
    }
    
    return 0;
}


/** 
 * Lookup for dbSignatureObj in cacheSignatureObj 
 * @note compare message,sid,gid and revision.
 * @note Used in context db->internaCache lookup (if found remove CACHE_INTERNAL_ONLY and set CACHE_BOTH flag)
 *
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t dbSignatureLookup(dbSignatureObj *iLookup,cacheSignatureObj *iHead)
{
    
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbSignatureObj[0x%x] cacheSignatureObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
    
    if(iHead == NULL)
    {
        return 0;
    }
    
    while(iHead != NULL)
    {
	if( (strncasecmp(iLookup->message,iHead->obj.message,
			 glsl(iLookup->message,iHead->obj.message)) == 0) &&
	    (iLookup->sid == iHead->obj.sid) &&
	    (iLookup->gid == iHead->obj.gid))
        {
	    /* Found */
   
	    /* 
	       If the object in current list has a revision of 0, 
	       and that a match is found for gid/sid (we are probably being called from the initialization 
	       (should) and the current node is 
	       initialized with information from the files only, and probably the database has cleaner information)
	       set the revision to the revision of the lookup node, 
	       but if the revision is not set to 0 and does
	       not match, continue searching.
	    */
	    
	    if(iHead->obj.rev == 0)
	    {
		iHead->obj.rev = iLookup->rev;
	    }
	    else
	    {
		if( iHead->obj.rev != iLookup->rev)
		{
		    /* It is not the signature object that we are looking for */
		    goto next_obj;
		}
	    }
	    
	    if(  iHead->flag & CACHE_INTERNAL_ONLY)
	    {
		iHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
	    }
	    else
	    {
		iHead->flag ^= CACHE_BOTH;
	    }
	    
	    /* NOTE: -elz For cleanness this should be removed from here, moved to the caller and add a 
	       param for the found node.. but since its only called from one place, this is currently 
		   how its done...lazyness first.
	    */
	    /* Set values from the database */
	    iHead->obj.db_id = iLookup->db_id;
	    iHead->obj.class_id = iLookup->class_id;
	    iHead->obj.priority_id = iLookup->priority_id;
	    return 1;
	}
	
    next_obj:
	iHead = iHead->next;
    }    
    
    return 0;

}


/** 
 * Lookup for dbClassificationObj in cacheClassificationObj 
 * @note Used in context db->internaCache lookup (if found remove CACHE_INTERNAL_ONLY and set CACHE_BOTH flag)
 * 
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t dbClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead)
{
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbReferenceObj[0x%x] cacheClassificationObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
    
    if(iHead == NULL)
    {
	return 0;
    }
    
    while(iHead != NULL)
    {
	if( (strncasecmp(iLookup->sig_class_name,iHead->obj.sig_class_name,
			 glsl(iLookup->sig_class_name,iHead->obj.sig_class_name)) == 0))
	{
            /* Found */
	    if(  iHead->flag & CACHE_INTERNAL_ONLY)
            {
                iHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
            }
            else
            {
                iHead->flag ^= CACHE_BOTH;
            }
	    iHead->obj.db_sig_class_id = iLookup->db_sig_class_id;
            return 1;
        }
	
        iHead = iHead->next;
    }
    
    return 0;
}

/* 
   
   iHead->system == lookup for system obj
   iHead = reference lookup for system.
   
*/

/** 
 * This function will convert the system cache and the reference cache.
 * This as a twist since there is an issue in the map parsing code 
 * We get reference before system, so we have to lookup for system first
 * which is ref->system, then we lookup for reference node in the system node.
 * if not present we create the system node then use that system node to insert the reference which is the
 * parent, ignore next for both cases since we do not traverse list because of the way its built.
 *
 * @param iHead 
 * @param iMasterCache 
 * @param cSobj 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ConvertReferenceCache(ReferenceNode *iHead,MasterCache *iMasterCache,cacheSignatureObj *cSobj,DatabaseData *data)
{
    
    ReferenceNode *cNode = NULL;
    cacheReferenceObj *ref_TobjNode = NULL;
    cacheReferenceObj *retRefLookupNode = NULL;
    dbReferenceObj ref_LobjNode = {0};    
    cacheSystemObj *sys_TobjNode = NULL;
    cacheSystemObj *sysRetCacheNode = NULL;
    dbSystemObj sys_LobjNode = {0};    
    
    u_int32_t tItr = 0;
    u_int32_t refFound = 0;
    
    if( (iMasterCache == NULL) || 
	(cSobj == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if(iHead == NULL)
    {
	/* Nothing to do */
	return 0;
    }
    
    cNode = iHead;
    
    while(cNode != NULL)
    {
	memset(&sys_LobjNode,'\0',sizeof(dbSystemObj));
	
	if(cNode->system != NULL)
	{
	    strncpy(sys_LobjNode.ref_system_name,cNode->system->name,SYSTEM_NAME_LEN);
	    sys_LobjNode.ref_system_name[SYSTEM_NAME_LEN-1] = '\0'; //safety

	    if( (snort_escape_string_STATIC(sys_LobjNode.ref_system_name,SYSTEM_NAME_LEN,data)))
	    {
		FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
			   "[%s], Exiting. \n",
			   __FUNCTION__,
			   sys_LobjNode.ref_system_name);
	    }

	}
	
	if(cNode->system->url != NULL)
	{
	    strncpy(sys_LobjNode.ref_system_url,cNode->system->url,SYSTEM_URL_LEN);
	    sys_LobjNode.ref_system_url[SYSTEM_URL_LEN-1] = '\0'; //safety

	    if( (snort_escape_string_STATIC(sys_LobjNode.ref_system_url,SYSTEM_URL_LEN,data)))
            {
                FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                           "[%s], Exiting. \n",
                           __FUNCTION__,
                           sys_LobjNode.ref_system_url);
            }
	}
	
	sysRetCacheNode = NULL;

	if(cacheSystemLookup(&sys_LobjNode,iMasterCache->cacheSystemHead,&sysRetCacheNode) == 0)
	{
	    if( (sys_TobjNode = SnortAlloc(sizeof(cacheSystemObj))) == NULL)
	    {
		/* XXX */
		return 1;
	    }

#if DEBUG
            file_system_object_count++;
#endif
	    memcpy(&sys_TobjNode->obj,&sys_LobjNode,sizeof(dbSystemObj));
	    
	    sys_TobjNode->flag = CACHE_INTERNAL_ONLY;
	    
	    sys_TobjNode->next = iMasterCache->cacheSystemHead;
	    iMasterCache->cacheSystemHead = sys_TobjNode;
	    
	    sysRetCacheNode = sys_TobjNode;
	}
	
	if(sysRetCacheNode != NULL)
	{
	    //Populate the lookup reference object
	    memset(&ref_LobjNode,'\0',sizeof(dbReferenceObj));
	    
	    strncpy(ref_LobjNode.ref_tag,cNode->id,REF_TAG_LEN);
	    ref_LobjNode.ref_tag[REF_TAG_LEN-1] = '\0'; //safety			
	    
	    
	    if( (snort_escape_string_STATIC(ref_LobjNode.ref_tag,REF_TAG_LEN,data)))
	    {
		FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
			   "[%s], Exiting. \n",
			   __FUNCTION__,
			   ref_LobjNode.ref_tag);
	    }
	    
	    
	    /* Lookup Reference node */
	    if((cacheReferenceLookup(&ref_LobjNode,sysRetCacheNode->obj.refList,&retRefLookupNode) == 0))
	    {
		if( (ref_TobjNode = SnortAlloc(sizeof(cacheReferenceObj))) == NULL)
		{
		    /* XXX */
		    return 1;
		}
		
#if DEBUG
		file_reference_object_count++;
#endif
		memcpy(&ref_TobjNode->obj,&ref_LobjNode,sizeof(dbReferenceObj));	    
		
		ref_TobjNode->flag ^= CACHE_INTERNAL_ONLY;
		
		ref_TobjNode->next = sysRetCacheNode->obj.refList;
		sysRetCacheNode->obj.refList = ref_TobjNode;
		
		ref_TobjNode->obj.parent = sysRetCacheNode;
		
		if( cSobj->obj.ref_count < MAX_REF_OBJ)
		{
		    cSobj->obj.ref[cSobj->obj.ref_count] = ref_TobjNode;
		    cSobj->obj.ref_count++;
		}
	    }
	    else
	    {
		/* Found in reference node, is it already defined in the signature object? */
		refFound = 0;
		for(tItr=0; tItr < cSobj->obj.ref_count; tItr++)
		{
		    if( (memcmp(&cSobj->obj.ref[tItr]->obj,&retRefLookupNode->obj,sizeof(dbReferenceObj))) == 0)
		    {
			refFound = 1;
			break;
		    }
		}
		
		if(refFound == 0)
		{
		    if( cSobj->obj.ref_count < MAX_REF_OBJ)
		    {
			cSobj->obj.ref[cSobj->obj.ref_count] =  retRefLookupNode;
			cSobj->obj.ref_count++;
		    }
		}
	    }
	}
	else
	{
	    /* XXX */
	    return 1;
	}

	cNode = cNode->next;
    }


    return 0;
}
/* 
   ^
   |
   |
   These function are slightly different since they are recurssively called by each signatures 
   call to ConvertSignatureCache()
*/


u_int32_t SignatureCacheInsertObj(dbSignatureObj *iSigObj,MasterCache *iMasterCache,u_int32_t from)
{
    cacheSignatureObj *TobjNode = NULL;
    
    if( (iMasterCache == NULL) ||
	(iSigObj == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (TobjNode = SnortAlloc(sizeof(cacheSignatureObj))) == NULL)
    {
	/* XXX */
	return 1;
    }
    
    memcpy(&TobjNode->obj,iSigObj,sizeof(dbSignatureObj));

    if( from == 0)
    {
	TobjNode->flag ^= CACHE_INTERNAL_ONLY;
    }
    else
    {
	TobjNode->flag ^= CACHE_BOTH;
    }

    TobjNode->next = iMasterCache->cacheSignatureHead;
    iMasterCache->cacheSignatureHead = TobjNode;
    
    return 0;
}



/** 
 * This function will convert the signature cache.
 * 
 * @param iHead 
 * @param iMasterCache 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ConvertSignatureCache(SigNode **iHead,MasterCache *iMasterCache,DatabaseData *data)
{
    SigNode *cNode = NULL;
    cacheSignatureObj *TobjNode = NULL;    
    dbSignatureObj lookupNode = {0};    

    if( (iHead == NULL) ||
	(iMasterCache == NULL) || 
	(data == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (cNode = *iHead) == NULL)
    {
        /* Nothing to do */
        return 0;
    }
    
    while(cNode != NULL)
    {

	memset(&lookupNode,'\0',sizeof(dbSignatureObj));
	
	lookupNode.gid  = cNode->generator;
        lookupNode.sid  = cNode->id;
        lookupNode.rev  = cNode->rev;
        lookupNode.class_id  = cNode->class_id;
        lookupNode.priority_id  = cNode->priority;
	
	if( cNode->msg != NULL)
	{
	    strncpy(lookupNode.message,cNode->msg,SIG_MSG_LEN);
	    lookupNode.message[SIG_MSG_LEN-1] = '\0'; //safety
	    
	    
	    if( (snort_escape_string_STATIC(lookupNode.message,SIG_MSG_LEN,data)))
            {
                FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                           "[%s], Exiting. \n",
                           __FUNCTION__,
                           lookupNode.message);
            }
	}
	else
	{
	    snprintf(lookupNode.message, SIG_MSG_LEN,
		     "Snort Alert [%u:%u:%u]",
		     lookupNode.gid,
		     lookupNode.sid,
		     lookupNode.rev);
	}
	
	//Do not allow duplicate to exist
	if( (cacheSignatureLookup(&lookupNode,iMasterCache->cacheSignatureHead) == 0) )
	{
	    if( (TobjNode = SnortAlloc(sizeof(cacheSignatureObj))) == NULL)
	    {
		/* XXX */
		return 1;
	    }
	    
	    memcpy(&TobjNode->obj,&lookupNode,sizeof(dbSignatureObj));
	    
	    TobjNode->flag ^= CACHE_INTERNAL_ONLY;
	    
	    TobjNode->next = iMasterCache->cacheSignatureHead;
	    iMasterCache->cacheSignatureHead = TobjNode;
	    
	    if(cNode->refs != NULL)
	    {
		if( (ConvertReferenceCache(cNode->refs,iMasterCache,TobjNode,data)))
		{
		    /* XXX */
		    return 1;
		}
	    }
#if DEBUG	
	    file_signature_object_count++;
#endif 
	    
	}
	else
	{
	    LogMessage("WARNING: While processing data parsed from SIGNATURE FILE a duplicate entry was found [DUPLICATE ARE NOT PROCESSED]:\n"
		       "\tGenerator ID:[%u] \tSignature ID:[%u] \tRevision:[%u] Classification ID:[%u] \t \n"
		       "\tMessage  [%s]\n",
		       lookupNode.gid,
		       lookupNode.sid,
		       lookupNode.rev,
		       lookupNode.class_id,
		       lookupNode.message);
	}


	cNode = cNode->next;
    }
    
    return 0;
}


/** 
 * This function will convert the classification cache. 
 * 
 * @param iHead 
 * @param iMasterCache 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ConvertClassificationCache(ClassType **iHead, MasterCache *iMasterCache,DatabaseData *data)
{
    ClassType *cNode = NULL;
    cacheClassificationObj *TobjNode = NULL;
    cacheClassificationObj LobjNode;
    
    if( (iHead == NULL) ||
	(iMasterCache == NULL) ||
	(iMasterCache->cacheClassificationHead != NULL) ||
	(data == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (cNode = *iHead) == NULL)
    {
	LogMessage("[%s()], No classification was found in the classification file,\n"
                   "\t make sure that you have valid records in your database (sig_class) table, else this might result in complete signature logging. \n",
		   __FUNCTION__);
	return 0;
    }
    
    while(cNode != NULL)
    {
	
	memset(&LobjNode,'\0',sizeof(cacheClassificationObj));
	
	LobjNode.obj.sig_class_id = cNode->id;

	/* 
	   -- config classification:shortname,short description,priority
	   NOTE: -elz i wongly assumed , short description was logged, while it 
	   was actually shortname that should have been logged, this is why
	   this part of the code is now commented :)
	   so using cNode->type instead of cNode->name
	*/
	
	if(cNode->type != NULL)
	{
	    strncpy(LobjNode.obj.sig_class_name,cNode->type,CLASS_NAME_LEN);
	    LobjNode.obj.sig_class_name[CLASS_NAME_LEN-1] = '\0'; //safety.
	    
	    if( (snort_escape_string_STATIC(LobjNode.obj.sig_class_name,CLASS_NAME_LEN,data)))
	    {
		FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
			   "[%s], Exiting. \n",
			   __FUNCTION__,
			   LobjNode.obj.sig_class_name);
	    }
	    
	}
	else
	{
	    snprintf(LobjNode.obj.sig_class_name,CLASS_NAME_LEN,
		     "[%s] id:[%u]",
		     "UNKNOWN SNORT CLASSIFICATION",
		     LobjNode.obj.sig_class_id);
	}



	if( (cacheClassificationLookup(&LobjNode.obj,iMasterCache->cacheClassificationHead) == 0))
	{
	    if( (TobjNode = SnortAlloc(sizeof(cacheClassificationObj))) == NULL)
	    {
		/* XXX */
		return 1;
	    }
	    
	    memcpy(TobjNode,&LobjNode,sizeof(cacheClassificationObj));
	    
	    
	    TobjNode->flag ^= CACHE_INTERNAL_ONLY;
	    
	    TobjNode->next = iMasterCache->cacheClassificationHead;
	    iMasterCache->cacheClassificationHead = TobjNode;
	    
	    cNode = cNode->next;
#if DEBUG
	    file_classification_object_count++;
#endif
	}
    }
    
    return 0;
}


/***********************************************************************************************CLASSIFICATION API*/

/** 
 * Fetch Classification from database
 * 
 * @param data 
 * @param iArrayPtr 
 * @param array_length 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationPullDataStore(DatabaseData *data, dbClassificationObj **iArrayPtr,u_int32_t *array_length)
{

    
    
#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL))    
    u_int32_t curr_row = 0;
    u_int32_t queryColCount =0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)) */


#ifdef ENABLE_ODBC
    dbClassificationObj tClassObj = {0};
    SQLSMALLINT col_count = 0;
#endif /* ENABLE_ODBC */
    
#ifdef ENABLE_MYSQL
    int result = 0;
#endif

#ifdef ENABLE_POSTGRESQL
    char *pg_val = NULL;
    u_int32_t curr_col = 0;
    int num_row = 0;
    u_int8_t pgStatus = 0;
#endif /* ENABLE_POSTGRESQL */

    if( (data == NULL) ||
        ( ( iArrayPtr == NULL )  && ( *iArrayPtr != NULL )) ||
        ( array_length == NULL))
    { 
	/* XXX */
	LogMessage("[%s()], Call failed DataBaseData[0x%x] dbClassificationObj **[0x%x] u_int32_t *[0x%x] \n",
		   __FUNCTION__,
		   data,
		   iArrayPtr,
		   array_length);
	return 1;
    }
    
    
    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                       SQL_SELECT_ALL_CLASSIFICATION)!=  SNORT_SNPRINTF_SUCCESS))
    {
        FatalError("database [%s()], Unable to allocate memory for query, bailing ...\n",
		   __FUNCTION__);
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_MYSQL
	
    case DB_MYSQL:

        result = mysql_query(data->m_sock,data->SQL_SELECT);

        switch(result)
        {
        case 0:

            if( (data->m_result = mysql_store_result(data->m_sock)) == NULL)
            {
                /* XXX */
                LogMessage("[%s()], Failed call to mysql_store_result \n",
                           __FUNCTION__);
                return 1;
            }
            else
            {
		
                MYSQL_ROW row = NULL;
                my_ulonglong num_row = 0;
                unsigned int i = 0;
		
                if( (num_row = mysql_num_rows(data->m_result)) > 0)
                {
                    if( (*iArrayPtr = SnortAlloc( (sizeof(dbClassificationObj) * num_row))) == NULL)
		    {
			mysql_free_result(data->m_result);
			data->m_result = NULL;
			FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
				   __FUNCTION__);
		    }
		}
		else
		{

		    /* XXX */
		    if(iArrayPtr != NULL)
		    {
			free(*iArrayPtr);
			*iArrayPtr = NULL;
		    }
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()]: No Classification found in database ... \n",
                               __FUNCTION__);
		    return 0;
                }
		
		*array_length = num_row;
		
		queryColCount = mysql_num_fields(data->m_result);
		
                if(queryColCount != NUM_ROW_CLASSIFICATION)
                {
                    /* XXX */
                    free(*iArrayPtr);
		    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()] To many column returned by query [%u]...\n",
                               __FUNCTION__,
                               queryColCount);
                    return 1;
                }
		
                while ((curr_row < num_row) &&
                       (row = mysql_fetch_row(data->m_result)))
                {

		    dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];
		    
                    for(i = 0; i < queryColCount; i++)
                    {
                        unsigned long *lengths={0};
			
                        if( (lengths = mysql_fetch_lengths(data->m_result)) == NULL)
                        {
                            free(*iArrayPtr);
			    *iArrayPtr = NULL;
                            mysql_free_result(data->m_result);
                            data->m_result = NULL;
                            FatalError("database [%s()], mysql_fetch_lengths() call failed .. \n",
                                       __FUNCTION__);
                        }
			
                        if(row[i])
			{
                            switch (i)
                            {
                            case 0:
                                cPtr->db_sig_class_id = strtoul(row[i],NULL,10);
                                break;
				
                            case 1:
                                strncpy(cPtr->sig_class_name,row[i],CLASS_NAME_LEN);
				cPtr->sig_class_name[CLASS_NAME_LEN-1] = '\0'; //safety

				if( (snort_escape_string_STATIC(cPtr->sig_class_name,CLASS_NAME_LEN,data)))
				{
				    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
					       "[%s], Exiting. \n",
					       __FUNCTION__,
					       cPtr->sig_class_name);
				}


                                break;
				
                            default:
                                /* XXX */
                                /* Should bail here... */
                                break;
                            }
			}
		    }
		    
		    
                    curr_row++;
                }
		                
                mysql_free_result(data->m_result);
                data->m_result = NULL;
                return 0;
            }
            break;
	    
	    
        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
	    
            if(checkTransactionState(data->dbRH))
            {
                LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n Failed QUERY: [%s] \n",
                           __FUNCTION__,
                           mysql_error(data->m_sock),
                           data->SQL_SELECT);
                return 1;
            }
	    
            LogMessage("[%s()]: Failed exeuting query [%s] , will retry \n",
                       __FUNCTION__,
                       data->SQL_SELECT);
	    break;
	    
        }
	
        /* XXX */
        return 1;
        break;
#endif /* ENABLE_MYSQL */
	    
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:
	
	data->p_result = PQexec(data->p_connection,data->SQL_SELECT);
	
	pgStatus = PQresultStatus(data->p_result);
	switch(pgStatus)
	    {
		
	    case PGRES_TUPLES_OK:
		
		if( (num_row = PQntuples(data->p_result)))
		{

		    *array_length = num_row;
		    
		    if( (queryColCount = PQnfields(data->p_result)) !=  NUM_ROW_CLASSIFICATION)
		    {
			LogMessage("[%s()] To many column returned by query [%u]...\n",
				   __FUNCTION__,
				   queryColCount);
			PQclear(data->p_result);
			data->p_result = NULL;
			return 1;
		    }
		    
		    
		    if( (*iArrayPtr = SnortAlloc( (sizeof(dbClassificationObj) * num_row))) == NULL)
		    {
			if(data->p_result)
			{
			    PQclear(data->p_result);
			    data->p_result = NULL;
			}
			FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
				   __FUNCTION__);
		    }
		    
		    for(curr_row = 0 ; curr_row < num_row ; curr_row++)
		    {
			dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];
			
			for(curr_col = 0 ; curr_col < queryColCount ; curr_col ++)
			{
			    pg_val = NULL;
			    if( (pg_val = PQgetvalue(data->p_result,curr_row,curr_col)) == NULL)
			    {
				/* XXX */
				/* Something went wrong */
				PQclear(data->p_result);
				data->p_result = NULL;
				return 1;
			    }		
			    
			    switch(curr_col)
			    {
			    case 0:
				cPtr->db_sig_class_id = strtoul(pg_val,NULL,10);
				break;
			    case 1:
				strncpy(cPtr->sig_class_name,pg_val,CLASS_NAME_LEN);
				cPtr->sig_class_name[CLASS_NAME_LEN-1] = '\0'; //safety

				if( (snort_escape_string_STATIC(cPtr->sig_class_name,CLASS_NAME_LEN,data)))
                                {
                                    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                                               "[%s], Exiting. \n",
                                               __FUNCTION__,
                                               cPtr->sig_class_name);
                                }


				break;
			    default:
				/* We should bail here*/
				break;
			    }
			}
		    }
		}
		else
		{
		    *array_length = 0;
		}
		
		
		if(data->p_result)
		{
		    PQclear(data->p_result);
		    data->p_result = NULL;
		}
		
		return 0;
		break;
		
	    default:
		if(PQerrorMessage(data->p_connection)[0] != '\0')
		{
		    ErrorMessage("ERROR database: postgresql_error: %s\n",
				 PQerrorMessage(data->p_connection));
		    return 1;
		}
		break;
	    }
	    
	    return 1;
	    break;
	    
#endif /* ENABLE_POSTGRESQL */
	    
	    
#ifdef ENABLE_ODBC
	case DB_ODBC:

	    if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	    {
		if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)data->SQL_SELECT, SQL_NTS) == SQL_SUCCESS)
		{
		    if( SQLNumResultCols(data->u_statement,&col_count) == SQL_SUCCESS)
		    {
			if(col_count == NUM_ROW_CLASSIFICATION)
			{
			    if(SQLRowCount(data->u_statement, &data->u_rows) != SQL_SUCCESS)
			    {
				ODBCPrintError(data,SQL_HANDLE_STMT);
				FatalError("[%s()]: SQLRowCount() call failed \n",
					   __FUNCTION__);
			    }
			    
				if(data->u_rows)
				{
				    if( (*iArrayPtr = SnortAlloc( (sizeof(dbClassificationObj) * data->u_rows))) == NULL)
				    {
					goto ODBCError;
				    }
				    
				    *array_length = data->u_rows;

				}
				else
				{
				    /* We have no records */
				    *array_length = 0;
				    return 0;
				}
				
			    }
			    else
			    {
				FatalError("[%s()]: The number of column returned does not match [%u] \n",
					   __FUNCTION__,
					   NUM_ROW_CLASSIFICATION);
			    }
		    }
		    else
		    {
			LogMessage("[%s()]: SQLNumResultCols() call failed \n",
				   __FUNCTION__);
			ODBCPrintError(data,SQL_HANDLE_STMT);
			goto ODBCError;
		    }
		    
		}
		else
		{
		    LogMessage("[%s()]: SQLExecDirect() call failed \n",
			       __FUNCTION__);
			ODBCPrintError(data,SQL_HANDLE_STMT);
			goto ODBCError;
			
		}
	    }
	    else
	    {
		LogMessage("[%s()]: SQLAllocStmt() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    SQLINTEGER col1_len = 0;
	    SQLINTEGER col2_len = 0;
	    
	    /* Bind template object */
	    if( SQLBindCol(data->u_statement,1,SQL_C_LONG,&tClassObj.db_sig_class_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLBindCol() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    if( SQLBindCol(data->u_statement,2,SQL_C_CHAR,&tClassObj.sig_class_name,(sizeof(char) * CLASS_NAME_LEN) ,&col2_len) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLBindCol() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    for(curr_row = 0; curr_row < data->u_rows;curr_row++)
	    {
		dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];
		
                /* fetch */
		if( SQLFetch(data->u_statement) != SQL_SUCCESS)
		{
		    LogMessage("[%s()]: SQLFetch error on record [%u] \n",
			       __FUNCTION__,
			       curr_row+1);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		}
		else
		{
		    if( (col1_len == SQL_NO_TOTAL || col1_len == SQL_NULL_DATA) ||
			(col2_len == SQL_NO_TOTAL || col2_len == SQL_NULL_DATA))
		    {
			FatalError("[%s()] Seem's like we have some null data ...\n",
				   __FUNCTION__);
		    }
		    
		    
		    /* Copy object */
		    if( (memcpy(cPtr,&tClassObj,sizeof(dbClassificationObj))) != cPtr)
		    {
			FatalError("[%s()] : memcpy error ..\n",
				   __FUNCTION__);
		    }
		    
		    /* Clear temp obj */
		    memset(&tClassObj,'\0',sizeof(dbClassificationObj));
		}
	    }

	    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	    return 0;

    ODBCError:
	    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	    return 1;
	    

	    break;
#endif /* ENABLE_ODBC */
	    
#ifdef ENABLE_ORACLE
    case DB_ORACLE:
	LogMessage("[%s()], is not yet implemented for DBMS configured\n",
		   __FUNCTION__);
	
	break;
#endif /* ENABLE_ORACLE */
	
	
#ifdef ENABLE_MSSQL
    case DB_MSSQL:
	LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
	break;
#endif /* ENABLE_MSSQL */
	    
    default:
	
	LogMessage("[%s()], is not yet implemented for DBMS configured\n",
		   __FUNCTION__);
	break;
	
	return 1;
    }
    
    /* XXX */
    return 1;
}
    



	   

/** 
 *  Merge internal Classification cache with database data, detect difference, tag known node for database update
 * 
 * @param iDBList 
 * @param array_length 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationCacheUpdateDBid(dbClassificationObj *iDBList,u_int32_t array_length,cacheClassificationObj **cacheHead)
{


    cacheClassificationObj *TobjNode = NULL;    
    dbClassificationObj *cObj = NULL;

    int x = 0;

    if( ((iDBList == NULL) ||
	 (array_length == 0) ||
	 (cacheHead == NULL)))
    {
	/* XXX */
	return 1;
    }


    /* Set default db object classification id as invocation require */
    for(x = 0 ; x < array_length ; x++)
    {
	cObj = &iDBList[x];
	cObj->sig_class_id = x+1;
    }
    
    for(x = 0 ; x < array_length ; x++)
    {
	cObj = &iDBList[x];
	
	if( (dbClassificationLookup(cObj,*cacheHead)) == 0 )
	{
	    /* Element not found, add the db entry to the list. */
	    
	    if( (TobjNode = SnortAlloc(sizeof(cacheClassificationObj))) == NULL)
	    {
		/* XXX */
		return 1;
	    }
	    
	    memcpy(&TobjNode->obj,cObj,sizeof(dbClassificationObj));
	    TobjNode->flag ^= CACHE_DATABASE_ONLY;
	    
	    if(*cacheHead == NULL)
	    {
		*cacheHead = TobjNode;
	    }
	    else
	    {
		TobjNode->next = *cacheHead;
		*cacheHead = TobjNode;
	    }
	}
    }

    return 0;
}


/** 
 *  Populate the sig_class table with record that are not present in the database.
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationPopulateDatabase(DatabaseData  *data,cacheClassificationObj *cacheHead)
{
    u_int32_t db_class_id;
    
    if( (data == NULL) ||
	(cacheHead == NULL))
    {
	/* XXX */
	return 1;
    }
	
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    BeginTransaction(data);
    
    while(cacheHead != NULL)
    {
	if(cacheHead->flag & CACHE_INTERNAL_ONLY)
	{
	    
#if DEBUG
            inserted_classification_object_count++;
#endif

	    /* DONE at object insertion
	      if( (snort_escape_string_STATIC(cacheHead->obj.sig_class_name,CLASS_NAME_LEN,data)))
	      {
	      FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
	      "[%s], Exiting. \n",
	      __FUNCTION__,
	      cacheHead->obj.sig_class_name);
	      }
	    */
	    
	    DatabaseCleanInsert(data);

	    if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
			       SQL_INSERT_CLASSIFICATION,
			       cacheHead->obj.sig_class_name)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }


	    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
			       SQL_SELECT_SPECIFIC_CLASSIFICATION,
			       cacheHead->obj.sig_class_name)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		    goto TransactionFail;
	    }
	
	    if(Insert(data->SQL_INSERT,data,1))
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    if(Select(data->SQL_SELECT,data,&db_class_id))
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    cacheHead->obj.db_sig_class_id = db_class_id;


	}
	cacheHead = cacheHead->next;


    }

    CommitTransaction(data);
    
    return 0;
    
TransactionFail:
    RollbackTransaction(data);
    return 1;
}

/** 
 * Wrapper function for classification cache synchronization
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationCacheSynchronize(DatabaseData *data,cacheClassificationObj **cacheHead)
{
    dbClassificationObj *dbClassArray = NULL;
    u_int32_t array_length = 0;
    
    if( (data == NULL) ||
	(cacheHead == NULL))
    {
	/* XXX */
       	return 1;
    }
    
    if( (ClassificationPullDataStore(data,&dbClassArray,&array_length)))
    {
	/* XXX */
	return 1;
    }

    
#if DEBUG
    db_classification_object_count=array_length;
#endif
    
    if( array_length > 0 )
    {
	if( (ClassificationCacheUpdateDBid(dbClassArray,array_length,cacheHead)) )
	{
	    /* XXX */
	    if( dbClassArray != NULL)
	    {
		free(dbClassArray);
		dbClassArray = NULL;
		array_length = 0;
	    }
	
	    LogMessage("[%s()], Call to ClassificationCacheUpdateDBid() failed \n",
		       __FUNCTION__);
	    return 1;
	}
	
	if(dbClassArray != NULL)
	{
	    free(dbClassArray);
	    dbClassArray = NULL;
	}
	array_length = 0;
    }
    
    
    if(*cacheHead == NULL)
    {
	LogMessage("\n[%s()]: Make sure that your (config classification_config argument in your barnyard2 configuration file) or --classification or -C argument point \n"
		   "\t to a file containing at least some valid classification or that that your database sig_class table contain data\n\n",
		   __FUNCTION__);
	return 1;
    }
    
    if(*cacheHead != NULL)
    {
	if(ClassificationPopulateDatabase(data,*cacheHead))
	{
	    LogMessage("[%s()], Call to ClassificationPopulateDatabase() failed \n",
		       __FUNCTION__);
	    
	    return 1;
	}
    }
    
    /* out list will behave now */
    return 0;
}

/***********************************************************************************************CLASSIFICATION API*/

/***********************************************************************************************SIGNATURE API*/



/** 
 * Lookup the database for a specific signature, without looking for signature message.
 * 
 * @param data 
 * @param sObj 
 * 
 * @return 
 * 0 OK (Found)
 * 1 ERROR (Not Found)
 */
u_int32_t SignatureLookupDatabase(DatabaseData *data,dbSignatureObj *sObj)
{

    u_int32_t db_sig_id = 0;

    if( (data == NULL) ||
	(sObj == NULL))
    {
	/* XXX */
	return 1;
    }

    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
		       SQL_SELECT_SPECIFIC_SIGNATURE_WITHOUT_MESSAGE,
		       sObj->sid,
		       sObj->gid,
		       sObj->rev,
		       sObj->class_id,
		       sObj->priority_id)) !=  SNORT_SNPRINTF_SUCCESS)
    {
	/* XXX */
	return 1;
    }
    
#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()] Signature was not found in cache, looking for existance in the database:\n"
			    "\t if this message occur to often, make sure your sid-msg.map and gen-msg.map file are up to date.\n"
			    "\t Executing [%s]\n",
			    __FUNCTION__,
			    data->SQL_SELECT));
#endif
    
    /* 
       This usleep is mainly to prevent uncontrolable collision, since this code could be executed in parallel
       pretty fast to create the race condition anyways, there is a chance adding a small delay that someone will win the race
    */
    usleep(400);
    /* 
       This usleep is mainly to prevent uncontrolable collision, since this code could be executed in parallel
       pretty fast to create the race condition anyways, there is a chance adding a small delay that someone will win the race
    */	

    if(Select(data->SQL_SELECT,data,&db_sig_id))
    {
	/* XXX */
	return 1;
    }
    
    if(db_sig_id == 0)
    {
	
#if DEBUG
	DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()]: A lookup received a result but a result of 0 shouldn't be returned,\n"
				"\t this shouldn't happen for sid[%u] sid[%u] rev[%u] class_id[%u] priority_id[%u] \n",
				__FUNCTION__,
				sObj->sid,
				sObj->gid,
				sObj->rev,
				sObj->class_id,
				sObj->priority_id));
#endif
	return 1;
    }
    
    /* Found */
    sObj->db_id = db_sig_id;
    return 0;
}



/** 
 *  Populate the signature table with record that are not present in the database.
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignaturePopulateDatabase(DatabaseData  *data,cacheSignatureObj *cacheHead,int inTransac)
{
    u_int32_t db_sig_id = 0;


    if( (data == NULL) ||
	(cacheHead == NULL))
    {
	/* XXX */
	return 1;
    }

    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    if(inTransac == 0)
    {
	if( (BeginTransaction(data)))
	{
	    /* XXX */
	    return 1;
	}
    }
        
    while(cacheHead != NULL)
    {
	
	/* This condition block is a shortcut in the signature insertion code.
	** Preventing signature that have not been under "revision" (rev == 0) to be inserted in the database.
	** It will also prevent the code to take wrong execution path downstream.
	*/
	if( ((cacheHead->flag & CACHE_INTERNAL_ONLY) && 
	     (((cacheHead->obj.gid != 1 && cacheHead->obj.gid != 3)) ||
	      ((cacheHead->obj.gid == 1 || cacheHead->obj.gid == 3) && cacheHead->obj.rev != 0))))
	{
	/* This condition block is a shortcut in the signature insertion code.
	** Preventing signature that have not been under "revision" (rev == 0) to be inserted in the database.
	** It will also prevent the code to take wrong execution path downstream.
	*/

	    
#if DEBUG
	    inserted_signature_object_count++;
#endif 
	    /* DONE at object Insertion
	      if( (snort_escape_string_STATIC(cacheHead->obj.message,SIG_MSG_LEN,data)))
	      {
	      FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
	      "[%s], Exiting. \n",
	      __FUNCTION__,
	      cacheHead->obj.message);
	      }
	    */

	    DatabaseCleanInsert(data);


	    if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
			       SQL_INSERT_SIGNATURE,
			       cacheHead->obj.sid,
			       cacheHead->obj.gid,
			       cacheHead->obj.rev,
			       cacheHead->obj.class_id,
			       cacheHead->obj.priority_id,
			       cacheHead->obj.message)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		    /* XXX */
		goto TransactionFail;
	    }
		    
	    DatabaseCleanSelect(data);

	    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
			       SQL_SELECT_SPECIFIC_SIGNATURE,
			       cacheHead->obj.sid,
			       cacheHead->obj.gid,
			       cacheHead->obj.rev,
			       cacheHead->obj.class_id,
			       cacheHead->obj.priority_id,
			       cacheHead->obj.message)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }
		    
	    if(Insert(data->SQL_INSERT,data,1))
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    if(Select(data->SQL_SELECT,data,&db_sig_id))
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    cacheHead->obj.db_id = db_sig_id;

	    
	    cacheHead->flag ^=  (CACHE_INTERNAL_ONLY | CACHE_BOTH);
	}

	cacheHead = cacheHead->next;


    }
    
    
    if(inTransac == 0)
    {
	if(CommitTransaction(data))
	{
	    /* XXX */
	    return 1;
	}
    }
    
    return 0;
    
TransactionFail:
    if( inTransac == 0)
    {
	RollbackTransaction(data);
    }

    return 1;    
}

/** 
 *  Merge internal Signature cache with database data, detect difference, tag known node for database update
 * @param iDBList 
 * @param array_length 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignatureCacheUpdateDBid(dbSignatureObj *iDBList,u_int32_t array_length,cacheSignatureObj **cacheHead)
{
    dbSignatureObj *cObj = NULL;
    cacheSignatureObj *TobjNode = NULL;
    int x = 0;
    
    if( ((iDBList == NULL) || 
	 (array_length == 0) ||
	 (cacheHead == NULL)))
    {
        /* XXX */
        return 1;
    }
    
    for(x = 0 ; x < array_length ; x++)
    {
        cObj = &iDBList[x];
	
        if( (dbSignatureLookup(cObj,*cacheHead)) == 0 )
        {
	    /* Element not found, add the db entry to the list. */
            if( (TobjNode = SnortAlloc(sizeof(cacheSignatureObj))) == NULL)
            {
		/* XXX */
		return 1;
            }
	    
            memcpy(&TobjNode->obj,cObj,sizeof(dbSignatureObj));
            TobjNode->flag ^= CACHE_DATABASE_ONLY;
	    
            if(*cacheHead == NULL)
            {
                *cacheHead = TobjNode;
            }
            else
            {
                TobjNode->next = *cacheHead;
                *cacheHead = TobjNode;
            }
        }
    }
    
    return 0;
}


/** 
 * Fetch Signature from database
 * 
 * @param data 
 * @param iArrayPtr 
 * @param array_length 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignaturePullDataStore(DatabaseData *data, dbSignatureObj **iArrayPtr,u_int32_t *array_length)
{

#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC))
    u_int32_t curr_row = 0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC)) */        
    

#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL))
      u_int32_t queryColCount =0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)) */

    
#ifdef ENABLE_ODBC
    dbSignatureObj tSigObj = {0};
    SQLSMALLINT col_count = 0;
#endif /* ENABLE_ODBC */

    
#ifdef ENABLE_MYSQL
    int result = 0;
#endif

    
#ifdef ENABLE_POSTGRESQL

    char *pg_val = NULL;
    int num_row = 0;
    u_int32_t curr_col = 0;    
    u_int8_t pgStatus = 0;
#endif /* ENABLE_POSTGRESQL */

    if( (data == NULL) ||
        ( ( iArrayPtr == NULL )  && ( *iArrayPtr != NULL )) ||
        ( array_length == NULL))
    { 
	/* XXX */
	LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSignatureObj **[0x%x] u_int32_t *[0x%x] \n",
		   __FUNCTION__,
		   data,
		   iArrayPtr,
		   array_length);
	return 1;
    }
    
    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                       SQL_SELECT_ALL_SIGNATURE)!=  SNORT_SNPRINTF_SUCCESS))
    {
        FatalError("database [%s()], Unable to allocate memory for query, bailing ...\n",
		   __FUNCTION__);
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_MYSQL
	
    case DB_MYSQL:

        result = mysql_query(data->m_sock,data->SQL_SELECT);

        switch(result)
        {
        case 0:

            if( (data->m_result = mysql_store_result(data->m_sock)) == NULL)
            {
                /* XXX */
                LogMessage("[%s()], Failed call to mysql_store_result \n",
                           __FUNCTION__);
                return 1;
            }
            else
            {
		
                MYSQL_ROW row = NULL;
                my_ulonglong num_row = 0;
                unsigned int i = 0;
		
                if( (num_row = mysql_num_rows(data->m_result)) > 0)
                {
                    if( (*iArrayPtr = SnortAlloc( (sizeof(dbSignatureObj) * num_row))) == NULL)
		    {
			mysql_free_result(data->m_result);
			data->m_result = NULL;
			FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
				   __FUNCTION__);
		    }
		}
		else
		{
		    /* XXX */
		    free(*iArrayPtr);
		    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()]: No signature found in database ... \n",
                               __FUNCTION__);
		    return 0;
                }
		
		*array_length = num_row;
		
		queryColCount = mysql_num_fields(data->m_result);
		
                if(queryColCount != NUM_ROW_SIGNATURE)
                {
                    /* XXX */
                    free(*iArrayPtr);
		    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()] To many column returned by query [%u]...\n",
                               __FUNCTION__,
                               queryColCount);
                    return 1;
                }
		
                while ((curr_row < num_row) &&
                       (row = mysql_fetch_row(data->m_result)))
                {

		    dbSignatureObj *cPtr = &(*iArrayPtr)[curr_row];
		    
		    for(i = 0; i < queryColCount; i++)
                    {
                        unsigned long *lengths={0};
			
                        if( (lengths = mysql_fetch_lengths(data->m_result)) == NULL)
                        {
                            free(*iArrayPtr);
			    *iArrayPtr = NULL;
                            mysql_free_result(data->m_result);
                            data->m_result = NULL;
                            FatalError("database [%s()], mysql_fetch_lengths() call failed .. \n",
                                       __FUNCTION__);
                        }
						
                        if( (row[i] != NULL) )
			{
                            switch (i)
                            {
				
                            case 0:
                                cPtr->db_id = strtoul(row[i],NULL,10);
                                break;
				
                            case 1:
				cPtr->sid= strtoul(row[i],NULL,10);
                                break;
				
			    case 2:
				cPtr->gid = strtoul(row[i],NULL,10);
				break;
				
			    case 3:
				cPtr->rev = strtoul(row[i],NULL,10);
				break;
				
			    case 4:
				cPtr->class_id = strtoul(row[i],NULL,10);
				break;
				
			    case 5:
				cPtr->priority_id = strtoul(row[i],NULL,10);
				break;
				
			    case 6:
				strncpy(cPtr->message,row[i],SIG_MSG_LEN);
				cPtr->message[SIG_MSG_LEN-1] = '\0'; //safety
				
                                //Safety escape value.
				if( (snort_escape_string_STATIC(cPtr->message,SIG_MSG_LEN,data)))
				{
				    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
					       "[%s], Exiting. \n",
					       __FUNCTION__,
					       cPtr->message);
				}
				break;
				
                            default:
                                /* XXX */
                                /* Should bail here... */
                                break;
                            }
			}
		    }
		    curr_row++;
                }
		
                mysql_free_result(data->m_result);
                data->m_result = NULL;
                return 0;
            }
            break;
	    
	    
        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
	    
            if(checkTransactionState(data->dbRH))
            {
                LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n Failed QUERY: [%s] \n",
                           __FUNCTION__,
                           mysql_error(data->m_sock),
                           data->SQL_SELECT);
                return 1;
            }
	    
            LogMessage("[%s()]: Failed exeuting query [%s] , will retry \n",
                       __FUNCTION__,
                       data->SQL_SELECT);
	    break;

        }

        /* XXX */
        return 1;

        break;

#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

        data->p_result = PQexec(data->p_connection,data->SQL_SELECT);

        pgStatus = PQresultStatus(data->p_result);
        switch(pgStatus)
	{

	case PGRES_TUPLES_OK:

	    if( (num_row = PQntuples(data->p_result)))
	    {
		*array_length = num_row;
		
		if( (queryColCount = PQnfields(data->p_result)) !=  NUM_ROW_SIGNATURE)
		{
		    LogMessage("[%s()] To many column returned by query [%u]...\n",
			       __FUNCTION__,
			       queryColCount);
		    PQclear(data->p_result);
		    data->p_result = NULL;
		    return 1;
		}
		
		if( (*iArrayPtr = SnortAlloc( (sizeof(dbSignatureObj) * num_row))) == NULL)
		{
		    if(data->p_result)
		    {
			PQclear(data->p_result);
			data->p_result = NULL;
		    }
		    FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
			       __FUNCTION__);
		}

		for(curr_row = 0 ; curr_row < num_row ; curr_row++)
		{
		    dbSignatureObj *cPtr = &(*iArrayPtr)[curr_row];

		    for(curr_col = 0 ; curr_col < queryColCount ; curr_col ++)
		    {
			pg_val = NULL;
			if( (pg_val = PQgetvalue(data->p_result,curr_row,curr_col)) == NULL)
			{
			    /* XXX */
			    /* Something went wrong */
			    PQclear(data->p_result);
			    data->p_result = NULL;
			    return 1;
			}
			switch(curr_col)
			{
			case 0:
			    cPtr->db_id = strtoul(pg_val,NULL,10);
			    break;

			case 1:
			    cPtr->sid= strtoul(pg_val,NULL,10);
			    break;

			case 2:
			    cPtr->gid = strtoul(pg_val,NULL,10);
			    break;

			case 3:
			    cPtr->rev = strtoul(pg_val,NULL,10);
			    break;

			case 4:
			    cPtr->class_id = strtoul(pg_val,NULL,10);
			    break;

			case 5:
			    cPtr->priority_id = strtoul(pg_val,NULL,10);
			    break;

			case 6:
			    strncpy(cPtr->message,pg_val,SIG_MSG_LEN);
			    cPtr->message[SIG_MSG_LEN-1] = '\0'; //safety

			    //Safety escape value.
			    if( (snort_escape_string_STATIC(cPtr->message,SIG_MSG_LEN,data)))
			    {
				FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
					   "[%s], Exiting. \n",
					   __FUNCTION__,
					   cPtr->message);
			    }
			    break;

			default:
			    /* We should bail here*/
			    break;
			}
		    }
		}
	    }
	    else
	    {
		*array_length = 0;
	    }


	    if(data->p_result)
	    {
		PQclear(data->p_result);
		data->p_result = NULL;
	    }

	    return 0;
	    break;

	default:
	    if(PQerrorMessage(data->p_connection)[0] != '\0')
	    {
		ErrorMessage("ERROR database: postgresql_error: %s\n",
			     PQerrorMessage(data->p_connection));
		return 1;
	    }
	    break;
	}

	return 1;
	break;


#endif /* ENABLE_POSTGRESQL */


#ifdef ENABLE_ODBC
    case DB_ODBC:
        if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	{
	    if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)data->SQL_SELECT, SQL_NTS) == SQL_SUCCESS)
            {
		    if( SQLNumResultCols(data->u_statement,&col_count) == SQL_SUCCESS)
		    {
			if(col_count ==  NUM_ROW_SIGNATURE)
			{
			    if(SQLRowCount(data->u_statement, &data->u_rows) != SQL_SUCCESS)
			    {
				ODBCPrintError(data,SQL_HANDLE_STMT);
				FatalError("[%s()]: SQLRowCount() call failed \n",
					   __FUNCTION__);
			    }

			    if(data->u_rows)
			    {
				if( (*iArrayPtr = SnortAlloc( (sizeof(dbSignatureObj) * data->u_rows))) == NULL)
				{
				    goto ODBCError;
				}

				*array_length = data->u_rows;

			    }
			    else
			    {
				/* We have no records */
				*array_length = 0;
				return 0;
			    }

			}
			else
			{
			    FatalError("[%s()]: The number of column returned does not match [%u] \n",
				       __FUNCTION__,
				       NUM_ROW_SIGNATURE);
			}
		    }
		    else
		    {
			LogMessage("[%s()]: SQLNumResultCols() call failed \n",
				   __FUNCTION__);
			ODBCPrintError(data,SQL_HANDLE_STMT);
			goto ODBCError;
		    }
	    }
	    else
	    {
		LogMessage("[%s()]: SQLExecDirect() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
		
	    }
	}
	else
	{
	    LogMessage("[%s()]: SQLAllocStmt() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}

	SQLINTEGER col1_len = 0;
	SQLINTEGER col2_len = 0;
	SQLINTEGER col3_len = 0;
	SQLINTEGER col4_len = 0;
	SQLINTEGER col5_len = 0;
	SQLINTEGER col6_len = 0;
	SQLINTEGER col7_len = 0;
	
	/* Bind template object */
	if( SQLBindCol(data->u_statement,1,SQL_C_LONG,&tSigObj.db_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,2,SQL_C_LONG,&tSigObj.sid,sizeof(u_int32_t),&col2_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,3,SQL_C_LONG,&tSigObj.gid,sizeof(u_int32_t) ,&col3_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,4,SQL_C_LONG,&tSigObj.rev,sizeof(u_int32_t) ,&col4_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}

	if( SQLBindCol(data->u_statement,5,SQL_C_LONG,&tSigObj.class_id,sizeof(u_int32_t) ,&col4_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,6,SQL_C_LONG,&tSigObj.priority_id,sizeof(u_int32_t) ,&col5_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}								
	
	if( SQLBindCol(data->u_statement,7,SQL_C_CHAR,tSigObj.message, (sizeof(char)*SIG_MSG_LEN) ,&col6_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	for(curr_row = 0; curr_row < data->u_rows ;curr_row++)
	{
	    dbSignatureObj *cPtr = &(*iArrayPtr)[curr_row];
	    
	    /* fetch */
	    if( SQLFetch(data->u_statement) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLFetch error on record [%u] \n",
			   __FUNCTION__,
			   curr_row+1);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    else
	    {
		if( (col1_len == SQL_NO_TOTAL || col1_len == SQL_NULL_DATA) ||
		    (col2_len == SQL_NO_TOTAL || col2_len == SQL_NULL_DATA) ||
		    (col3_len == SQL_NO_TOTAL || col3_len == SQL_NULL_DATA) ||
		    (col4_len == SQL_NO_TOTAL || col4_len == SQL_NULL_DATA) ||
		    (col5_len == SQL_NO_TOTAL || col5_len == SQL_NULL_DATA) ||
		    (col6_len == SQL_NO_TOTAL || col6_len == SQL_NULL_DATA) ||
		    (col7_len == SQL_NO_TOTAL || col7_len == SQL_NULL_DATA))
		{
		    FatalError("[%s()] Seem's like we have some null data ...\n",
			       __FUNCTION__);
		}
		
		/* Copy object */
		if( (memcpy(cPtr,&tSigObj,sizeof(dbSignatureObj))) != cPtr)
		{
		    FatalError("[%s()] : memcpy error ..\n",
			       __FUNCTION__);
		}
		
		cPtr->message[SIG_MSG_LEN-1] = '\0';
		if( (snort_escape_string_STATIC(cPtr->message,SIG_MSG_LEN,data)))
		{
		    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
			       "[%s], Exiting. \n",
			       __FUNCTION__,
			       cPtr->message);
		}
		
		/* Clear temp obj */
		memset(&tSigObj,'\0',sizeof(dbSignatureObj));
	    }
	}


	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	return 0;

    ODBCError:
	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	return 1;

        break;
#endif /* ENABLE_ODBC */

#ifdef ENABLE_ORACLE
    case DB_ORACLE:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);

        break;
#endif /* ENABLE_ORACLE */


	
#ifdef ENABLE_MSSQL
    case DB_MSSQL:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;
#endif /* ENABLE_MSSQL */
	
    default:
	
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;
	
    }
    
    return 0;
}


/**
 * Find signature with the same SID and GID and set Ref. If Ref is found, 
 * also check for CACHE_BOTH FLAG
 *
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignatureReferencePreGenerate(cacheSignatureObj *iHead)
{
    cacheSignatureObj *cObj = NULL;
    cacheSignatureObj *searchObj = NULL;
    if( iHead == NULL)
    {
	/* XXX */
	return 1;
    }
    
    cObj = iHead;

    while(cObj != NULL)
    {
	if( (cObj->flag & CACHE_BOTH) &&
	    (cObj->obj.rev != 0) &&
	    (cObj->obj.ref_count > 0))
	{
	    searchObj = iHead;
	    
	    while(searchObj != NULL)
	    {
		if( (searchObj != cObj) &&
		    (cObj->obj.sid == searchObj->obj.sid) &&
		    (cObj->obj.gid == searchObj->obj.gid) &&
		    /* Only set lesser revision rule with refs */
		    (cObj->obj.rev < searchObj->obj.rev))
		{
		    searchObj->obj.ref_count = cObj->obj.ref_count;
		    memcpy(searchObj->obj.ref,cObj->obj.ref, (sizeof(cacheReferenceObj *)*MAX_REF_OBJ));
		}
		
		searchObj = searchObj->next;
	    }
	}
	
	cObj = cObj->next;
    }
    
    return 0;

}

/** 
 * Wrapper function for signature cache synchronization
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignatureCacheSynchronize(DatabaseData *data,cacheSignatureObj **cacheHead)
{

    dbSignatureObj *dbSigArray = NULL;
    u_int32_t array_length = 0;
    
    if( (data == NULL) ||
        (*cacheHead == NULL))
    {
        /* XXX */
        return 1;
    }
    
    if( (SignaturePullDataStore(data,&dbSigArray,&array_length)))
    {
        /* XXX */
        return 1;
    }

#if DEBUG
    db_signature_object_count=array_length;
#endif

    if( array_length > 0 )
    {
        if( (SignatureCacheUpdateDBid(dbSigArray,array_length,cacheHead)) )
        {
            /* XXX */
            if( dbSigArray != NULL)
            {
                free(dbSigArray);
                dbSigArray = NULL;
                array_length = 0;
            }
	    
            LogMessage("[%s()], Call to SignatureCacheUpdateDBid() failed \n",
                       __FUNCTION__);
            return 1;
        }
	
        if(dbSigArray != NULL)
        {
            free(dbSigArray);
            dbSigArray = NULL;
        }
        array_length = 0;
    }
    
    
    if(SignaturePopulateDatabase(data,*cacheHead,0))
    {
        LogMessage("[%s()], Call to SignaturePopulateDatabase() failed \n",
                   __FUNCTION__);
	return 1;
    }

    /* Equilibrate references thru sibblings.*/
    if(SignatureReferencePreGenerate(*cacheHead))
    {
	LogMessage("[%s()], Call to SignatureReferencePreGenerate failed \n",
		   __FUNCTION__);
	return 1;
    }

    /* Well done */
    return 0;
}




/***********************************************************************************************SYSTEM API*/
/*
** Those update system and reference 
*/
/***********************************************************************************************SYSTEM API*/

/** 
 * Fetch Reference  from database
 * 
 * @param data 
 * @param iArrayPtr 
 * @param array_length 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ReferencePullDataStore(DatabaseData *data, dbReferenceObj **iArrayPtr,u_int32_t *array_length)
{

#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC))
    u_int32_t curr_row = 0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC)) */        
    
#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL))    
    u_int32_t queryColCount =0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)) */
    
#ifdef ENABLE_ODBC
    dbReferenceObj tRefObj = {0};
    SQLSMALLINT col_count = 0;
#endif /* ENABLE_ODBC */

#ifdef ENABLE_MYSQL
    int result = 0;
#endif

#ifdef ENABLE_POSTGRESQL
    char *pg_val = NULL;
    int num_row = 0;
    u_int32_t curr_col = 0;
    u_int8_t pgStatus = 0;
#endif /* ENABLE_POSTGRESQL */

    
    
    if( (data == NULL) ||
        ( ( iArrayPtr == NULL )  && ( *iArrayPtr != NULL )) ||
        ( array_length == NULL))
    {
        /* XXX */
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSystemObj **[0x%x] u_int32_t *[0x%x] \n",
                   __FUNCTION__,
                   data,
                   iArrayPtr,
                   array_length);
        return 1;
    }

    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                       SQL_SELECT_ALL_REF) !=  SNORT_SNPRINTF_SUCCESS))
    {
        FatalError("database [%s()], Unable to allocate memory for query, bailing ...\n",
                   __FUNCTION__);
    }

    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    switch(data->dbtype_id)
    {
#ifdef ENABLE_MYSQL
	
    case DB_MYSQL:
	
        result = mysql_query(data->m_sock,data->SQL_SELECT);
	
        switch(result)
        {
        case 0:
            if( (data->m_result = mysql_store_result(data->m_sock)) == NULL)
            {
                /* XXX */
                LogMessage("[%s()], Failed call to mysql_store_result \n",
                           __FUNCTION__);
                return 1;
            }
            else
            {

                MYSQL_ROW row = NULL;
                my_ulonglong num_row = 0;
                unsigned int i = 0;
		
                if( (num_row = mysql_num_rows(data->m_result)) > 0)
                {
                    if( (*iArrayPtr = SnortAlloc( (sizeof(dbReferenceObj) * num_row))) == NULL)
                    {
                        mysql_free_result(data->m_result);
                        data->m_result = NULL;
                        FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                                   __FUNCTION__);
                    }
                }
                else
                {
                    /* XXX */
                    free(*iArrayPtr);
                    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()]: No Reference found in database ... \n",
                               __FUNCTION__);
                    return 0;
                }
		
                *array_length = num_row;
		
                queryColCount = mysql_num_fields(data->m_result);
		
                if(queryColCount != NUM_ROW_REF)
                {
                    /* XXX */
                    free(*iArrayPtr);
                    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()] To many column returned by query [%u]...\n",
                               __FUNCTION__,
                               queryColCount);
                    return 1;
                }
		
                while ((curr_row < num_row) &&
                       (row = mysql_fetch_row(data->m_result)))
                {
		    
                    dbReferenceObj *cPtr = &(*iArrayPtr)[curr_row];
		    
                    for(i = 0; i < queryColCount; i++)
                    {
                        unsigned long *lengths={0};
			
                        if( (lengths = mysql_fetch_lengths(data->m_result)) == NULL)
                        {
                            free(*iArrayPtr);
                            *iArrayPtr = NULL;
                            mysql_free_result(data->m_result);
                            data->m_result = NULL;
                            FatalError("database [%s()], mysql_fetch_lengths() call failed .. \n",
                                       __FUNCTION__);
                        }
			
                        if( (row[i] != NULL) )
                        {
                            switch (i)
                            {

                            case 0:
                                cPtr->ref_id = strtoul(row[i],NULL,10);
                                break;
				
                            case 1:
				/* Do nothing for now but could be used to do a consistency check */
				cPtr->system_id = strtoul(row[i],NULL,10);
				break;
				
			    case 2:
				strncpy(cPtr->ref_tag,row[i],REF_TAG_LEN);
				cPtr->ref_tag[REF_TAG_LEN-1] = '\0'; //toasty.
				
				//Safety escape value.
                                if( (snort_escape_string_STATIC(cPtr->ref_tag,REF_TAG_LEN,data)))
                                {
                                    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                                               "[%s], Exiting. \n",
                                               __FUNCTION__,
                                               cPtr->ref_tag);
                                }
				

				break;

                            default:
                                /* XXX */
                                /* Should bail here... */
                                break;
                            }
                        }
                    }
                    curr_row++;
                }
                
		
		mysql_free_result(data->m_result);
                data->m_result = NULL;
                return 0;
            }
            break;


        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:

            if(checkTransactionState(data->dbRH))
            {
                LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n Failed QUERY: [%s] \n",
                           __FUNCTION__,
                           mysql_error(data->m_sock),
                           data->SQL_SELECT);
                return 1;
            }

            LogMessage("[%s()]: Failed exeuting query [%s] , will retry \n",
                       __FUNCTION__,
                       data->SQL_SELECT);
            break;

        }

        /* XXX */
        return 1;
        break;

#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

        data->p_result = PQexec(data->p_connection,data->SQL_SELECT);

        pgStatus = PQresultStatus(data->p_result);
        switch(pgStatus)
	{

	case PGRES_TUPLES_OK:

	    if( (num_row = PQntuples(data->p_result)))
	    {

		*array_length = num_row;

		if( (queryColCount = PQnfields(data->p_result)) !=  NUM_ROW_REF)
		{
		    LogMessage("[%s()] To many column returned by query [%u]...\n",
			       __FUNCTION__,
			       queryColCount);
		    PQclear(data->p_result);
		    data->p_result = NULL;
		    return 1;
		}


		if( (*iArrayPtr = SnortAlloc( (sizeof(dbReferenceObj) * num_row))) == NULL)
		{
		    if(data->p_result)
		    {
			PQclear(data->p_result);
			data->p_result = NULL;
		    }

		    FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
			       __FUNCTION__);
		}

		for(curr_row = 0 ; curr_row < num_row ; curr_row++)
		{
		    dbReferenceObj *cPtr = &(*iArrayPtr)[curr_row];

		    for(curr_col = 0 ; curr_col < queryColCount ; curr_col ++)
		    {
			pg_val = NULL;
			if( (pg_val = PQgetvalue(data->p_result,curr_row,curr_col)) == NULL)
			{
			    /* XXX */
			    /* Something went wrong */
			    PQclear(data->p_result);
			    data->p_result = NULL;
			    return 1;
			}
			switch(curr_col)
			{
			case 0:
			    cPtr->ref_id = strtoul(pg_val,NULL,10);
			    break;

			case 1:
			    /* Do nothing for now but could be used to do a consistency check */
			    cPtr->system_id = strtoul(pg_val,NULL,10);
			    break;

			case 2:
			    strncpy(cPtr->ref_tag,pg_val,REF_TAG_LEN);
			    cPtr->ref_tag[REF_TAG_LEN-1] = '\0'; //toasty.
			    
			    //Safety escape value.
			    if( (snort_escape_string_STATIC(cPtr->ref_tag,REF_TAG_LEN,data)))
			    {
				FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
					   "[%s], Exiting. \n",
					   __FUNCTION__,
					   cPtr->ref_tag);
			    }


			    break;

			default:
			    /* We should bail here*/
			    break;
			}
		    }
		}
	    }
	    else
	    {
		*array_length = 0;
	    }


	    if(data->p_result)
	    {
		PQclear(data->p_result);
		data->p_result = NULL;
	    }

	    return 0;
	    break;

	default:
	    if(PQerrorMessage(data->p_connection)[0] != '\0')
	    {
		ErrorMessage("ERROR database: postgresql_error: %s\n",
			     PQerrorMessage(data->p_connection));
		return 1;
	    }
	    break;
	}

	return 1;
	break;

#endif /* ENABLE_POSTGRESQL */

#ifdef ENABLE_ODBC
    case DB_ODBC:
	if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	{
	    if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)data->SQL_SELECT, SQL_NTS) == SQL_SUCCESS)
            {
		if( SQLNumResultCols(data->u_statement,&col_count) == SQL_SUCCESS)
		{
		    if(col_count ==  NUM_ROW_REF)
		    {
			if(SQLRowCount(data->u_statement, &data->u_rows) != SQL_SUCCESS)
			{
			    ODBCPrintError(data,SQL_HANDLE_STMT);
			    FatalError("[%s()]: SQLRowCount() call failed \n",
				       __FUNCTION__);
			}
			
			if(data->u_rows)
			{
			    if( (*iArrayPtr = SnortAlloc( (sizeof(dbReferenceObj) * data->u_rows))) == NULL)
			    {
				goto ODBCError;
			    }
			    
			    *array_length = data->u_rows;
			    
			}
			else
			{
			    /* We have no records */
			    *array_length = 0;
			    return 0;
			}
			
		    }
		    else
		    {
			FatalError("[%s()]: The number of column returned does not match [%u] \n",
				   __FUNCTION__,
				   NUM_ROW_CLASSIFICATION);
		    }
		}
		else
		{
		    LogMessage("[%s()]: SQLNumResultCols() call failed \n",
			       __FUNCTION__);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		}
	    }
	    else
	    {
		LogMessage("[%s()]: SQLExecDirect() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	}
	else
	{
	    LogMessage("[%s()]: SQLAllocStmt() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	SQLINTEGER col1_len = 0;
	SQLINTEGER col2_len = 0;
	SQLINTEGER col3_len = 0;
	
	/* Bind template object */
	if( SQLBindCol(data->u_statement,1,SQL_C_LONG,&tRefObj.ref_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,2,SQL_C_LONG,&tRefObj.system_id,sizeof(u_int32_t),&col2_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,3,SQL_C_CHAR,&tRefObj.ref_tag,(sizeof(char) *REF_TAG_LEN) ,&col3_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}

	for(curr_row = 0; curr_row < data->u_rows;curr_row++)
	{
	    dbReferenceObj *cPtr = &(*iArrayPtr)[curr_row];
	    
	    /* fetch */
	    if( SQLFetch(data->u_statement) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLFetch error on record [%u] \n",
			   __FUNCTION__,
			   curr_row+1);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    else
	    {
		if( (col1_len == SQL_NO_TOTAL || col1_len == SQL_NULL_DATA) ||
		    (col2_len == SQL_NO_TOTAL || col2_len == SQL_NULL_DATA) ||
		    (col3_len == SQL_NO_TOTAL || col3_len == SQL_NULL_DATA))
		{
		    FatalError("[%s()] Seem's like we have some null data ...\n",
			       __FUNCTION__);
		}
		
		/* Copy object */
		if( (memcpy(cPtr,&tRefObj,sizeof(dbReferenceObj))) != cPtr)
		{
		    FatalError("[%s()] : memcpy error ..\n",
			       __FUNCTION__);
		}
		
		/* Clear temp obj */
		memset(&tRefObj,'\0',sizeof(dbReferenceObj));
	    }
	}
	

	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	return 0;
	
    ODBCError:

	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	return 1;
	
        break;
#endif /* ENABLE_ODBC */

#ifdef ENABLE_ORACLE
    case DB_ORACLE:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);

        break;
#endif /* ENABLE_ORACLE */

#ifdef ENABLE_MSSQL
    case DB_MSSQL:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;
#endif /* ENABLE_MSSQL */

    default:

        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;

    }

    return 0;
}


/** 
 * Fetch System from database
 * 
 * @param data 
 * @param iArrayPtr 
 * @param array_length 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SystemPullDataStore(DatabaseData *data, dbSystemObj **iArrayPtr,u_int32_t *array_length)
{

#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC))
    u_int32_t curr_row = 0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC)) */    

#if (defined(ENABLE_ODBC))
    dbSystemObj tSystemObj = {0};
    SQLSMALLINT col_count = 0;
#endif /* (defined(ENABLE_ODBC)) */
    
#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL))    
    u_int32_t queryColCount =0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)) */
    
#ifdef ENABLE_MYSQL
    int result = 0;
#endif

#ifdef ENABLE_POSTGRESQL
    char *pg_val = NULL;
    int num_row = 0;
    u_int32_t curr_col = 0;
    u_int8_t pgStatus = 0;
#endif /* ENABLE_POSTGRESQL */


    if( (data == NULL) ||
        ( ( iArrayPtr == NULL )  && ( *iArrayPtr != NULL )) ||
        ( array_length == NULL))
    {
        /* XXX */
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSystemObj **[0x%x] u_int32_t *[0x%x] \n",
                   __FUNCTION__,
                   data,
                   iArrayPtr,
                   array_length);
        return 1;
    }

    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                       SQL_SELECT_ALL_REFERENCE_SYSTEM) !=  SNORT_SNPRINTF_SUCCESS))
    {
        FatalError("database [%s()], Unable to allocate memory for query, bailing ...\n",
                   __FUNCTION__);
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_MYSQL
	
    case DB_MYSQL:
	
        result = mysql_query(data->m_sock,data->SQL_SELECT);
	
        switch(result)
        {
        case 0:
            if( (data->m_result = mysql_store_result(data->m_sock)) == NULL)
            {
                /* XXX */
                LogMessage("[%s()], Failed call to mysql_store_result \n",
                           __FUNCTION__);
                return 1;
            }
            else
            {
		
                MYSQL_ROW row = NULL;
                my_ulonglong num_row = 0;
                unsigned int i = 0;
		
                if( (num_row = mysql_num_rows(data->m_result)) > 0)
                {
                    if( (*iArrayPtr = SnortAlloc( (sizeof(dbSystemObj) * num_row))) == NULL)
                    {
                        mysql_free_result(data->m_result);
                        data->m_result = NULL;
                        FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                                   __FUNCTION__);
                    }
                }
                else
                {
                    /* XXX */
                    free(*iArrayPtr);
                    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()]: No System found in database ... \n",
                               __FUNCTION__);
                    return 0;
                }

                *array_length = num_row;

                queryColCount = mysql_num_fields(data->m_result);

                if(queryColCount != NUM_ROW_REFERENCE_SYSTEM)
                {
                    /* XXX */
                    free(*iArrayPtr);
                    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()] To many column returned by query [%u]...\n",
                               __FUNCTION__,
                               queryColCount);
                    return 1;
                }

                while ((curr_row < num_row) &&
                       (row = mysql_fetch_row(data->m_result)))
                {

                    dbSystemObj *cPtr = &(*iArrayPtr)[curr_row];

                    for(i = 0; i < queryColCount; i++)
                    {
                        unsigned long *lengths={0};

                        if( (lengths = mysql_fetch_lengths(data->m_result)) == NULL)
                        {
                            free(*iArrayPtr);
                            *iArrayPtr = NULL;
                            mysql_free_result(data->m_result);
                            data->m_result = NULL;
                            FatalError("database [%s()], mysql_fetch_lengths() call failed .. \n",
                                       __FUNCTION__);
                        }
			
			if( (row[i] != NULL) )
                        {
                            switch (i)
                            {
				
                            case 0:
                                cPtr->db_ref_system_id = strtoul(row[i],NULL,10);
                                break;
				
                            case 1:
                                strncpy(cPtr->ref_system_name,row[i],SYSTEM_NAME_LEN);
				cPtr->ref_system_name[SYSTEM_NAME_LEN-1] = '\0'; //toasty.

				//Safety escape value.
                                if( (snort_escape_string_STATIC(cPtr->ref_system_name,SYSTEM_NAME_LEN,data)))
                                {
                                    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                                               "[%s], Exiting. \n",
                                               __FUNCTION__,
                                               cPtr->ref_system_name);
                                }


                                break;
				
                            default:
                                /* XXX */
                                /* Should bail here... */
                                break;
                            }
                        }
                    }
                    curr_row++;
                }

                mysql_free_result(data->m_result);
                data->m_result = NULL;
                return 0;
            }
            break;


        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:

            if(checkTransactionState(data->dbRH))
            {
                LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n Failed QUERY: [%s] \n",
                           __FUNCTION__,
                           mysql_error(data->m_sock),
                           data->SQL_SELECT);
                return 1;
            }

            LogMessage("[%s()]: Failed exeuting query [%s] , will retry \n",
                       __FUNCTION__,
                       data->SQL_SELECT);
            break;

        }

        /* XXX */
        return 1;

        break;

#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

        data->p_result = PQexec(data->p_connection,data->SQL_SELECT);

        pgStatus = PQresultStatus(data->p_result);
        switch(pgStatus)
	{

	case PGRES_TUPLES_OK:

	    if( (num_row = PQntuples(data->p_result)))
	    {

		*array_length = num_row;

		if( (queryColCount = PQnfields(data->p_result)) !=  NUM_ROW_REFERENCE_SYSTEM)
		{
		    LogMessage("[%s()] To many column returned by query [%u]...\n",
			       __FUNCTION__,
			       queryColCount);
		    PQclear(data->p_result);
		    data->p_result = NULL;
		    return 1;
		}


		if( (*iArrayPtr = SnortAlloc( (sizeof(dbSystemObj) * num_row))) == NULL)
		{
		    if(data->p_result)
		    {
			PQclear(data->p_result);
			data->p_result = NULL;
		    }

		    FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
			       __FUNCTION__);
		}

		for(curr_row = 0 ; curr_row < num_row ; curr_row++)
		{
                    dbSystemObj *cPtr = &(*iArrayPtr)[curr_row];

		    for(curr_col = 0 ; curr_col < queryColCount ; curr_col ++)
		    {
			pg_val = NULL;
			if( (pg_val = PQgetvalue(data->p_result,curr_row,curr_col)) == NULL)
			{
			    /* XXX */
			    /* Something went wrong */
			    PQclear(data->p_result);
			    data->p_result = NULL;
			    return 1;
			}
			
			switch(curr_col)
			{
			    
			case 0:
			    cPtr->db_ref_system_id = strtoul(pg_val,NULL,10);
			    break;

			case 1:
			    strncpy(cPtr->ref_system_name,pg_val,SYSTEM_NAME_LEN);
			    cPtr->ref_system_name[SYSTEM_NAME_LEN-1] = '\0'; //toasty.

			    //Safety escape value.
			    if( (snort_escape_string_STATIC(cPtr->ref_system_name,SYSTEM_NAME_LEN,data)))
			    {
				FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
					   "[%s], Exiting. \n",
					   __FUNCTION__,
					   &cPtr->ref_system_name);
			    }


			    break;

			default:
			    /* We should bail here*/
			    break;
			}
		    }
		}
	    }
	    else
	    {
		*array_length = 0;
	    }


	    if(data->p_result)
	    {
		PQclear(data->p_result);
		data->p_result = NULL;
	    }

	    return 0;
	    break;

	default:
	    if(PQerrorMessage(data->p_connection)[0] != '\0')
	    {
		ErrorMessage("ERROR database: postgresql_error: %s\n",
			     PQerrorMessage(data->p_connection));
		return 1;
	    }
	    break;
	}

	return 1;
	break;

#endif /* ENABLE_POSTGRESQL */

#ifdef ENABLE_ODBC
    case DB_ODBC:

	if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	{

	    if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)data->SQL_SELECT, SQL_NTS) == SQL_SUCCESS)
	    {
		if( SQLNumResultCols(data->u_statement,&col_count) == SQL_SUCCESS)
		{
		    if(col_count == NUM_ROW_REFERENCE_SYSTEM)
		    {
			if(SQLRowCount(data->u_statement, &data->u_rows) != SQL_SUCCESS)
			{
			    ODBCPrintError(data,SQL_HANDLE_STMT);
			    FatalError("[%s()]: SQLRowCount() call failed \n",
				       __FUNCTION__);
			}
			
			if(data->u_rows)
			{
			    if( (*iArrayPtr = SnortAlloc( (sizeof(dbSystemObj) * data->u_rows))) == NULL)
			    {
				goto ODBCError;
			    }
			    
			    *array_length = data->u_rows;
			    
			}
			else
			{
			    /* We have no records */
			    *array_length = 0;
			    return 0;
			}
			
		    }
		    else
		    {
			FatalError("[%s()]: The number of column returned does not match [%u] \n",
				   __FUNCTION__,
				   NUM_ROW_REFERENCE_SYSTEM);
		    }
		}
		else
		{
			LogMessage("[%s()]: SQLNumResultCols() call failed \n",
				   __FUNCTION__);
			ODBCPrintError(data,SQL_HANDLE_STMT);
			goto ODBCError;
			}
		
	    }
	    else
	    {
		LogMessage("[%s()]: SQLExecDirect() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
		
	    }
	}
	else
	{
	    LogMessage("[%s()]: SQLAllocStmt() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	SQLINTEGER col1_len = 0;
	SQLINTEGER col2_len = 0;
	    
	    /* Bind template object */
	    if( SQLBindCol(data->u_statement,1,SQL_C_LONG,&tSystemObj.db_ref_system_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLBindCol() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    if( SQLBindCol(data->u_statement,2,SQL_C_CHAR,&tSystemObj.ref_system_name,(sizeof(char) * SYSTEM_NAME_LEN) ,&col2_len) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLBindCol() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    for(curr_row = 0; curr_row < data->u_rows;curr_row++)
	    {
		dbSystemObj *cPtr = &(*iArrayPtr)[curr_row];
		
                /* fetch */
		if( SQLFetch(data->u_statement) != SQL_SUCCESS)
		{
		    LogMessage("[%s()]: SQLFetch error on record [%u] \n",
			       __FUNCTION__,
			       curr_row+1);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		}
		else
		{
		    if( (col1_len == SQL_NO_TOTAL || col1_len == SQL_NULL_DATA) ||
			(col2_len == SQL_NO_TOTAL || col2_len == SQL_NULL_DATA))
		    {
			FatalError("[%s()] Seem's like we have some null data ...\n",
				   __FUNCTION__);
		    }
		    
		    
		    /* Copy object */
		    if( (memcpy(cPtr,&tSystemObj,sizeof(dbSystemObj))) != cPtr)
		    {
			FatalError("[%s()] : memcpy error ..\n",
				   __FUNCTION__);
		    }
		    
		    /* Clear temp obj */
		    memset(&tSystemObj,'\0',sizeof(dbSystemObj));
		}
	    }


	    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	    return 0;

    ODBCError:
	    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	    return 1;

        break;
#endif /* ENABLE_ODBC */

#ifdef ENABLE_ORACLE
    case DB_ORACLE:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);

        break;
#endif /* ENABLE_ORACLE */

#ifdef ENABLE_MSSQL
    case DB_MSSQL:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;
#endif /* ENABLE_MSSQL */

    default:

        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;

    }

    return 0;
}


/** 
 *  Merge internal System cache with database data, detect difference, tag known node for database update
 * 
 * @param iDBList 
 * @param array_length 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SystemCacheUpdateDBid(dbSystemObj *iDBList,u_int32_t array_length,cacheSystemObj **cacheHead)
{
    dbSystemObj *cObj = NULL;
    cacheSystemObj *TobjNode = NULL;
    int x = 0;
    
    if( (iDBList == NULL) ||
        (array_length == 0) ||
        (cacheHead == NULL))
    {
        /* XXX */
        return 1;
    }
    
    for(x = 0 ; x < array_length ; x++)
    {
        cObj = &iDBList[x];
	
        if( (dbSystemLookup(cObj,*cacheHead)) == 0 )
        {
            /* Element not found, add the db entry to the list. */
	    
            if( (TobjNode = SnortAlloc(sizeof(cacheSystemObj))) == NULL)
            {
                /* XXX */
		LogMessage("[%s()]: Error Failed to allocate..\n",__FUNCTION__);
                return 1;
            }
	    
            memcpy(&TobjNode->obj,cObj,sizeof(dbSystemObj));
            TobjNode->flag ^= CACHE_DATABASE_ONLY;
	    
            if(*cacheHead == NULL)
            {
                *cacheHead = TobjNode;
            }
            else
            {
                TobjNode->next = *cacheHead;
                *cacheHead = TobjNode;
            }
        }
    }

    return 0;
}


/** 
 *  Merge internal Reference cache with database data, detect difference, tag known node for database update
 * 
 * @param iDBList 
 * @param array_length 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ReferenceCacheUpdateDBid(dbReferenceObj *iDBList,u_int32_t array_length,cacheSystemObj **cacheHead)
{
    cacheSystemObj *systemHead = NULL;
    cacheReferenceObj *TobjNode = NULL;
    dbReferenceObj *cObj = NULL;    
    
    int x = 0;
    
    if( (iDBList == NULL) ||
        (array_length == 0) ||
	(cacheHead == NULL))
    {
        /* XXX */
        return 1;
    }
    
    
/* Set CACHE_BOTH if matches */
    
    systemHead = *cacheHead;
    while(systemHead != NULL)
    {    
	for(x = 0 ; x < array_length ; x++)
	{
	    cObj = &iDBList[x];
	    
	    if(cObj->system_id == systemHead->obj.db_ref_system_id)
	    {
		if( (dbReferenceLookup(cObj,systemHead->obj.refList)) == 0)
		{
		    if( (TobjNode = SnortAlloc(sizeof(cacheReferenceObj))) == NULL)
		    {
			/* XXX */
			return 1;
		    }
		    
		    memcpy(&TobjNode->obj,cObj,sizeof(dbReferenceObj));
		    
		    TobjNode->flag = CACHE_DATABASE_ONLY;
		    
		    TobjNode->obj.parent = systemHead;
		    TobjNode->next = systemHead->obj.refList;
		    
		    systemHead->obj.refList = TobjNode;
		}
	    }
	}
	
	systemHead = systemHead->next;
    }
    return 0;
}

/** 
 *  Populate the reference table with record that are not present in the database.
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ReferencePopulateDatabase(DatabaseData  *data,cacheReferenceObj *cacheHead)
{
    u_int32_t db_ref_id;

    
    if( (data == NULL) ||
	(cacheHead == NULL))
    {
        /* XXX */
        return 1;
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    BeginTransaction(data);
    
    while(cacheHead != NULL)
    {
	if(cacheHead->flag & CACHE_INTERNAL_ONLY)
        {

#if DEBUG
            inserted_reference_object_count++;
#endif

	    /* Removed the escaping because we live escaped in the cache */
	    
	    DatabaseCleanInsert(data);
	    
	    if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
			       SQL_INSERT_SPECIFIC_REF,
			       cacheHead->obj.parent->obj.db_ref_system_id,
			       cacheHead->obj.ref_tag)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    DatabaseCleanSelect(data);

	    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
			       SQL_SELECT_SPECIFIC_REF,
			       cacheHead->obj.parent->obj.db_ref_system_id,
			       cacheHead->obj.ref_tag)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }

            if(Insert(data->SQL_INSERT,data,1))
            {
                /* XXX */
                goto TransactionFail;
            }

            if(Select(data->SQL_SELECT,data,&db_ref_id))
            {
                /* XXX */
                goto TransactionFail;
            }
	    
	    
            cacheHead->obj.ref_id = db_ref_id;
	    cacheHead->obj.system_id = cacheHead->obj.parent->obj.db_ref_system_id;
	    cacheHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH); /* Remove it */



        }
        
        cacheHead = cacheHead->next;
    }
    
    CommitTransaction(data);

    return 0;

TransactionFail:
    RollbackTransaction(data);
    return 1;
}


/** 
 *  Populate the system table with record that are not present in the database.
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SystemPopulateDatabase(DatabaseData  *data,cacheSystemObj *cacheHead)
{
    u_int32_t db_system_id = 0;

    if (data == NULL)
    {
        /* XXX */
        return 1;
    }

    if(cacheHead == NULL)
    {
	/* Nothing to do */
	return 0;
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    BeginTransaction(data);
    
    while(cacheHead != NULL)
    {
        if(cacheHead->flag & CACHE_INTERNAL_ONLY)
        {
#if DEBUG
            inserted_system_object_count++;
#endif


	    if( (snort_escape_string_STATIC(cacheHead->obj.ref_system_name,SYSTEM_NAME_LEN,data)))
            {
                FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                           "[%s], Exiting. \n",
                           __FUNCTION__,
                           cacheHead->obj.ref_system_name);
            }
	    
            DatabaseCleanInsert(data);
	    
	    if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
			       SQL_INSERT_SPECIFIC_REFERENCE_SYSTEM,
				   cacheHead->obj.ref_system_name)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }

	    DatabaseCleanSelect(data);
	
	    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
			       SQL_SELECT_SPECIFIC_REFERENCE_SYSTEM,
			       cacheHead->obj.ref_system_name)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }

            if(Insert(data->SQL_INSERT,data,1))
            {
                /* XXX */
                goto TransactionFail;
            }
	    
            if(Select(data->SQL_SELECT,data,&db_system_id))
            {
                /* XXX */
                goto TransactionFail;
            }
	    
	    cacheHead->obj.db_ref_system_id = db_system_id;
	    cacheHead->flag ^=  (CACHE_INTERNAL_ONLY | CACHE_BOTH); 
	    
	    /* Give child system id */
	    
	    cacheReferenceObj *tNode = cacheHead->obj.refList;
	    while(tNode != NULL)
	    {
		tNode->obj.parent = (cacheSystemObj *)&cacheHead->obj;
		tNode->obj.system_id = cacheHead->obj.db_ref_system_id;
		tNode = tNode->next;
	    }


        }


        cacheHead = cacheHead->next;
    }

    CommitTransaction(data);        

    return 0;

TransactionFail:
    RollbackTransaction(data);
    return 1;
}


/** 
 * Wrapper function for system cache synchronization
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SystemCacheSynchronize(DatabaseData *data,cacheSystemObj **cacheHead)
{
    
    cacheSystemObj *SystemCacheElemPtr = NULL;
    dbSystemObj *dbSysArray = NULL;
    dbReferenceObj *dbRefArray = NULL;	 
    
    u_int32_t array_length = 0;

    if( (data == NULL)  ||
        (*cacheHead == NULL))
    {
        /* XXX */
        return 1;
    }


    if( (SystemPullDataStore(data,&dbSysArray,&array_length)))
    {
        /* XXX */
        return 1;
    }
    
#if DEBUG
    db_system_object_count=array_length;
#endif


    //If system is not populated correctly, we probably do not have ref's
    //and if so using the schema logic they probably are wrong, thus
    // we will insert them by our self afterward.
    if( array_length > 0 )
    {
	if( (SystemCacheUpdateDBid(dbSysArray,array_length,cacheHead)) )
        {
            /* XXX */
	    LogMessage("[%s()], Call to SystemCacheUpdateDBid() failed. \n",
                       __FUNCTION__);
	    goto func_fail;
        }
    }
    
    /* Reset for re-use */
    array_length = 0;
    
    if( (ReferencePullDataStore(data,&dbRefArray,&array_length)))
    {
	/* XXX */
	LogMessage("[%s()], Call to ReferencePullDataStore() failed. \n",
		   __FUNCTION__);
	goto func_fail;
    }	
    
#if DEBUG
    db_reference_object_count=array_length;
#endif


    if(array_length > 0)
    {
	if( (ReferenceCacheUpdateDBid(dbRefArray,array_length,cacheHead)))
	{
	    /* XXX */
	    LogMessage("[%s()], Call to ReferenceCacheUpdateDBid() failed \n",
		       __FUNCTION__);
	    goto func_fail;
	}
    }
    
    /* Populate. */
    if(SystemPopulateDatabase(data,*cacheHead))
    {
        LogMessage("[%s()], Call to SystemPopulateDatabase() failed \n",
                   __FUNCTION__);
	goto func_fail;
    }
    
    /* Update Reference cache */
    SystemCacheElemPtr = *cacheHead;
    
    while(SystemCacheElemPtr != NULL)
    {
	if(SystemCacheElemPtr->obj.refList != NULL)
	{
	    if(ReferencePopulateDatabase(data,SystemCacheElemPtr->obj.refList))
	    {
		LogMessage("[%s()], Call to ReferencePopulateDatabase() failed \n",
			   __FUNCTION__);
		goto func_fail;
	    }
	}
	SystemCacheElemPtr = SystemCacheElemPtr->next;
    }
    
    if(dbRefArray != NULL)
    {
        free(dbRefArray);
        dbRefArray = NULL;
        array_length = 0;
    }
    
    if(dbSysArray != NULL)
    {
        free(dbSysArray);
        dbSysArray = NULL;
        array_length = 0;
    }
    
    return 0;
    
    
func_fail:
    if(dbRefArray != NULL)
    {
        free(dbRefArray);
        dbRefArray = NULL;
        array_length = 0;
    }

    if( dbSysArray != NULL)
    {
	free(dbSysArray);
	dbSysArray = NULL;
	array_length = 0;
    }
    
    return 1;
    
}
/***********************************************************************************************SYSTEM API*/
/*
** Those update system and reference 
*/
/***********************************************************************************************SYSTEM API*/



/***********************************************************************************************SIGREF API*/

/** 
 * 
 * 
 * @param iHead 
 * @param sigHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t GenerateSigRef(cacheSignatureReferenceObj **iHead,cacheSignatureObj *sigHead)
{
    cacheSignatureReferenceObj *newNode = NULL;
    dbSignatureReferenceObj lookupNode = {0};
    
    u_int32_t node_count = 0; //could be short eh!.
    
    if( (iHead == NULL) ||
	(sigHead == NULL))
    {
	/* XXX */
	return 1;
    }
    
    while(sigHead != NULL)
    {
	/* Do not generate sig_ref for internal sig, since they are not inserted, 
	   db_id is 0 and this is corrupting the process  */
	if(sigHead->obj.db_id != 0)
	{
	    for(node_count = 0; node_count < sigHead->obj.ref_count; node_count++)
	    {
		memset(&lookupNode,'\0',sizeof(dbSignatureReferenceObj));
		lookupNode.db_ref_id = sigHead->obj.ref[node_count]->obj.ref_id;	 
		lookupNode.db_sig_id = sigHead->obj.db_id;
		lookupNode.ref_seq = (node_count + 1);
		
		if( (cacheSignatureReferenceLookup(&lookupNode,*iHead)) == 0 )
		{
		    if( (newNode = SnortAlloc(sizeof(cacheSignatureReferenceObj))) == NULL)
		    {
			/* XXX */
			return 1;
		    }
		    
		    memcpy(&newNode->obj,&lookupNode,sizeof(dbSignatureReferenceObj));
		    newNode->flag ^= CACHE_INTERNAL_ONLY;
		    
		    newNode->next = *iHead;
		    *iHead = newNode;
#if DEBUG
		    file_sigref_object_count++;
#endif
		}
	    }
	}
        sigHead = sigHead->next;	
    }
    
    return 0;
}


/** 
 * Fetch SignatureReference from database
 * 
 * @param data 
 * @param iArrayPtr 
 * @param array_length 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignatureReferencePullDataStore(DatabaseData *data, dbSignatureReferenceObj **iArrayPtr,u_int32_t *array_length)
{

#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC))
    u_int32_t curr_row = 0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) || defined(ENABLE_ODBC)) */            
    
#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL))
    u_int32_t queryColCount =0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)) */
    
#ifdef ENABLE_ODBC
    dbSignatureReferenceObj tSigRefObj = {0};
    SQLSMALLINT col_count = 0;
#endif /* ENABLE_ODBC */
    
#ifdef ENABLE_MYSQL
    int result = 0;
#endif


#ifdef ENABLE_POSTGRESQL
    char *pg_val = NULL;
    int num_row = 0;
    u_int32_t curr_col = 0;
    u_int8_t pgStatus = 0;
#endif /* ENABLE_POSTGRESQL */

    
    if( (data == NULL) ||
        ( ( iArrayPtr == NULL )  && ( *iArrayPtr != NULL )) ||
        ( array_length == NULL))
    {
        /* XXX */
        LogMessage("[%s()], Call failed DataBaseData[0x%x] dbSystemObj **[0x%x] u_int32_t *[0x%x] \n",
                   __FUNCTION__,
                   data,
                   iArrayPtr,
                   array_length);
        return 1;
    }
    
    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                       SQL_SELECT_ALL_SIGREF) !=  SNORT_SNPRINTF_SUCCESS))
    {
        FatalError("database [%s()], Unable to allocate memory for query, bailing ...\n",
                   __FUNCTION__);
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    switch(data->dbtype_id)
    {

#ifdef ENABLE_MYSQL
    case DB_MYSQL:
	
        result = mysql_query(data->m_sock,data->SQL_SELECT);
	
        switch(result)
        {
        case 0:
            if( (data->m_result = mysql_store_result(data->m_sock)) == NULL)
            {
                /* XXX */
                LogMessage("[%s()], Failed call to mysql_store_result \n",
                           __FUNCTION__);
                return 1;
            }
            else
            {
		
                MYSQL_ROW row = NULL;
                my_ulonglong num_row = 0;
                unsigned int i = 0;
		
                if( (num_row = mysql_num_rows(data->m_result)) > 0)
                {
                    if( (*iArrayPtr = SnortAlloc( (sizeof(dbSignatureReferenceObj) * num_row))) == NULL)
                    {
                        mysql_free_result(data->m_result);
                        data->m_result = NULL;
                        FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
                                   __FUNCTION__);
                    }
                }
                else
                {
                    /* XXX */
                    free(*iArrayPtr);
                    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()]: No Reference found in database ... \n",
                               __FUNCTION__);
                    return 0;
                }
		
                *array_length = num_row;
		
                queryColCount = mysql_num_fields(data->m_result);
		
                if(queryColCount != NUM_ROW_SIGREF)
                {
                    /* XXX */
                    free(*iArrayPtr);
                    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()] To many column returned by query [%u]...\n",
                               __FUNCTION__,
                               queryColCount);
                    return 1;
                }

                while ((curr_row < num_row) &&
                       (row = mysql_fetch_row(data->m_result)))
                {
                    dbSignatureReferenceObj *cPtr = &(*iArrayPtr)[curr_row];
		    
                    for(i = 0; i < queryColCount; i++)
                    {
                        unsigned long *lengths={0};
			
                        if( (lengths = mysql_fetch_lengths(data->m_result)) == NULL)
                        {
                            free(*iArrayPtr);
                            *iArrayPtr = NULL;
                            mysql_free_result(data->m_result);
                            data->m_result = NULL;
                            FatalError("database [%s()], mysql_fetch_lengths() call failed .. \n",
                                       __FUNCTION__);
                        }
			
			switch (i)
			{
			case 0:
			    cPtr->db_ref_id = strtoul(row[i],NULL,10);
			    break;
			    
			case 1:
			    cPtr->db_sig_id = strtoul(row[i],NULL,10);
			    break;
			    
			case 2:
			    cPtr->ref_seq = strtoul(row[i],NULL,10);
				break;
				
			default:
			    /* XXX */
                                /* Should bail here... */
			    break;
			}
		    }
                    curr_row++;
                }
		
                mysql_free_result(data->m_result);
                data->m_result = NULL;
                return 0;
            }
            break;


        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:

            if(checkTransactionState(data->dbRH))
            {
                LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n Failed QUERY: [%s] \n",
                           __FUNCTION__,
                           mysql_error(data->m_sock),
                           data->SQL_SELECT);
                return 1;
            }

            LogMessage("[%s()]: Failed exeuting query [%s] , will retry \n",
                       __FUNCTION__,
                       data->SQL_SELECT);
            break;

        }

        /* XXX */
        return 1;
        break;

#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

        data->p_result = PQexec(data->p_connection,data->SQL_SELECT);

        pgStatus = PQresultStatus(data->p_result);
        switch(pgStatus)
	{

	case PGRES_TUPLES_OK:

	    if( (num_row = PQntuples(data->p_result)))
	    {

		*array_length = num_row;

		if( (queryColCount = PQnfields(data->p_result)) !=  NUM_ROW_SIGREF)
		{
		    LogMessage("[%s()] To many column returned by query [%u]...\n",
			       __FUNCTION__,
			       queryColCount);
		    PQclear(data->p_result);
		    data->p_result = NULL;
		    return 1;
		}


		if( (*iArrayPtr = SnortAlloc( (sizeof(dbSignatureReferenceObj) * num_row))) == NULL)
		{
		    if(data->p_result)
		    {
			PQclear(data->p_result);
			data->p_result = NULL;
		    }

		    FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
			       __FUNCTION__);
		}

		for(curr_row = 0 ; curr_row < num_row ; curr_row++)
		{
		    dbSignatureReferenceObj *cPtr = &(*iArrayPtr)[curr_row];

		    for(curr_col = 0 ; curr_col < queryColCount ; curr_col ++)
		    {
			pg_val = NULL;
			if( (pg_val = PQgetvalue(data->p_result,curr_row,curr_col)) == NULL)
			{
			    /* XXX */
			    /* Something went wrong */
			    PQclear(data->p_result);
			    data->p_result = NULL;
			    return 1;
			}

			switch(curr_col)
			{
			case 0:
                            cPtr->db_ref_id = strtoul(pg_val,NULL,10);
                            break;

                        case 1:
                            cPtr->db_sig_id = strtoul(pg_val,NULL,10);
                            break;

                        case 2:
                            cPtr->ref_seq = strtoul(pg_val,NULL,10);
			    break;

			default:
			    /* We should bail here*/
			    break;
			}
		    }
		}
	    }
	    else
	    {
		*array_length = 0;
	    }


	    if(data->p_result)
	    {
		PQclear(data->p_result);
		data->p_result = NULL;
	    }

	    return 0;
	    break;

	default:
	    if(PQerrorMessage(data->p_connection)[0] != '\0')
	    {
		ErrorMessage("ERROR database: postgresql_error: %s\n",
			     PQerrorMessage(data->p_connection));
		return 1;
	    }
	    break;
	}

	return 1;
	break;


#endif /* ENABLE_POSTGRESQL */

#ifdef ENABLE_ODBC
    case DB_ODBC:
	
	if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	{
	    if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)data->SQL_SELECT, SQL_NTS) == SQL_SUCCESS)
            {
		if( SQLNumResultCols(data->u_statement,&col_count) == SQL_SUCCESS)
		{
		    if(col_count == NUM_ROW_SIGREF)
		    {
			if(SQLRowCount(data->u_statement, &data->u_rows) != SQL_SUCCESS)
			{
			    ODBCPrintError(data,SQL_HANDLE_STMT);
			    FatalError("[%s()]: SQLRowCount() call failed \n",
				       __FUNCTION__);
			}
			
			if(data->u_rows)
			{
			    if( (*iArrayPtr = SnortAlloc( (sizeof(dbSignatureReferenceObj) * data->u_rows))) == NULL)
			    {
				goto ODBCError;
			    }
			    
			    *array_length = data->u_rows;
			}
			else
			{
			    /* We have no records */
			    *array_length = 0;
			    return 0;
			}
			
		    }
		    else
			{
			    FatalError("[%s()]: The number of column returned does not match [%u] \n",
				       __FUNCTION__,
				       NUM_ROW_CLASSIFICATION);
			}
		}
		else
		{
		    LogMessage("[%s()]: SQLNumResultCols() call failed \n",
			       __FUNCTION__);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		}
		
	    }
	    else
	    {
		    LogMessage("[%s()]: SQLExecDirect() call failed \n",
			       __FUNCTION__);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		    
	    }
	}
	else
	{
	    LogMessage("[%s()]: SQLAllocStmt() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	SQLINTEGER col1_len = 0;
	SQLINTEGER col2_len = 0;
	SQLINTEGER col3_len = 0;
	
	/* Bind template object */
	if( SQLBindCol(data->u_statement,1,SQL_C_LONG,&tSigRefObj.db_ref_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	}

	if( SQLBindCol(data->u_statement,2,SQL_C_LONG,&tSigRefObj.db_sig_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	if( SQLBindCol(data->u_statement,3,SQL_C_LONG,&tSigRefObj.ref_seq,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	{
	    LogMessage("[%s()]: SQLBindCol() call failed \n",
		       __FUNCTION__);
	    ODBCPrintError(data,SQL_HANDLE_STMT);
	    goto ODBCError;
	}
	
	    
	for(curr_row = 0; curr_row < data->u_rows;curr_row++)
	{
	    dbSignatureReferenceObj *cPtr = &(*iArrayPtr)[curr_row];
	    
	    /* fetch */
	    if( SQLFetch(data->u_statement) != SQL_SUCCESS)
		{
		    LogMessage("[%s()]: SQLFetch error on record [%u] \n",
			       __FUNCTION__,
			       curr_row+1);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		}
	    else
	    {
		if( (col1_len == SQL_NO_TOTAL || col1_len == SQL_NULL_DATA) ||
		    (col2_len == SQL_NO_TOTAL || col2_len == SQL_NULL_DATA) ||
		    (col3_len == SQL_NO_TOTAL || col3_len == SQL_NULL_DATA))
		{
		    FatalError("[%s()] Seem's like we have some null data ...\n",
			       __FUNCTION__);
		}
		
		/* Copy object */
		if( (memcpy(cPtr,&tSigRefObj,sizeof(dbSignatureReferenceObj))) != cPtr)
		{
		    FatalError("[%s()] : memcpy error ..\n",
			       __FUNCTION__);
		}
		
		/* Clear temp obj */
		memset(&tSigRefObj,'\0',sizeof(dbSignatureReferenceObj));
	    }
	}
	

	

	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	return 0;
	
    ODBCError:
	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	return 1;
	
        break;
#endif /* ENABLE_ODBC */
	
#ifdef ENABLE_ORACLE
    case DB_ORACLE:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);

        break;
#endif /* ENABLE_ORACLE */

#ifdef ENABLE_MSSQL
    case DB_MSSQL:
        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;
#endif /* ENABLE_MSSQL */

    default:

        LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
        break;

    }

    return 0;
}


/** 
 * get Signature node from cache where DBid match the lookup id.
 * 
 * @param iHead 
 * @param lookupId 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
cacheSignatureObj *cacheGetSignatureNodeUsingDBid(cacheSignatureObj *iHead,u_int32_t lookupId)
{
    while(iHead != NULL)
    {
	if(iHead->obj.db_id == lookupId)
	{
	    return iHead;
	}

	iHead = iHead->next;
    }
    
    return NULL;
}


/** 
 * get Reference node from cache where DBid match the lookup id.
 * 
 * @param iHead 
 * @param lookupId 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
cacheReferenceObj *cacheGetReferenceNodeUsingDBid(cacheSystemObj *iHead,u_int32_t lookupId)
{
    cacheReferenceObj *retRef = NULL;
    cacheReferenceObj *refPtr = NULL;
    
    while(iHead != NULL)
    {
	refPtr = iHead->obj.refList;
	
	while( (refPtr != NULL))
	{
	    if(refPtr->obj.ref_id)
	    {
		return refPtr;
	    }
	    
	    refPtr = refPtr->next;
	}
	iHead  =  iHead->next;
    }
    
    return retRef;
}



/** 
 *  Merge internal SignatureReference cache with database data, detect difference, tag known node for database update
 * 
 * @note This function cost alot but its the price to pay to sync and make sure we respect the db constraint
 *
 * @param iDBList 
 * @param array_length 
 * @param cacheHead 
 * @param sigCacheHead 
 * @param systemCacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignatureReferenceCacheUpdateDBid(dbSignatureReferenceObj *iDBList,
					    u_int32_t array_length,
					    cacheSignatureReferenceObj **cacheHead,
					    cacheSignatureObj *sigCacheHead,
					    cacheSystemObj *systemCacheHead)
{
    
    cacheSignatureReferenceObj *cCheck = NULL;    
    cacheSignatureReferenceObj *cacheLookup = NULL;
    cacheSignatureReferenceObj *tempCache = NULL;
    cacheSignatureReferenceObj *tNode = NULL;
    cacheSignatureReferenceObj *rNode = NULL;
    dbSignatureReferenceObj *cObj = NULL;

    u_int32_t databasemaxSeq = 0;
    u_int32_t sigRefFound = 0;
    u_int32_t sigSeq = 0;
    u_int32_t sigRefArr[MAX_REF_OBJ] = {0};

    int x = 0;
    
    if( (iDBList == NULL) ||
	(cacheHead == NULL) ||
	(sigCacheHead == NULL) ||
	(systemCacheHead == NULL) ||
	(array_length == 0))
    {
	/* XXX */
	return 1;
    }
    
    if( (iDBList == NULL))
    {
	/* XXX */
	/* No reference */
	return 0;
    }
    
    /* Build a temporary list from db records */
    for(x = 0 ; x < array_length ; x++)
    {
        cObj = &iDBList[x];
	
	if(tempCache != NULL)
	{
	    if( (dbSignatureReferenceLookup(cObj,tempCache,&rNode,0) == 0))
	    {
		if( (tNode = SnortAlloc(sizeof(cacheSignatureReferenceObj))) == NULL)
		{
		    /* XXX */
		    goto f_err;
		}
		
		memcpy(&tNode->obj,cObj,sizeof(dbSignatureReferenceObj));
		tNode->flag ^= CACHE_DATABASE_ONLY;
		tNode->next = tempCache;
		tempCache = tNode;
	    }
	    else
	    {
		LogMessage("Warning [%s()] : sig_id [%u] ref_id [%u] ref_seq [%u] Duplicate found in database with database constraint? Ignoring element in temporary cache \n",
			   cObj->db_sig_id,
			   cObj->db_ref_id,
			   cObj->ref_seq);
	    }
	}
	else
	{
	    if( (tNode = SnortAlloc(sizeof(cacheSignatureReferenceObj))) == NULL)
	    {
		/* XXX */
		goto f_err;
	    }
	    memcpy(&tNode->obj,cObj,sizeof(dbSignatureReferenceObj));
	    tNode->flag ^= CACHE_DATABASE_ONLY;
	    tNode->next = tempCache;
	    tempCache = tNode;
	    
	}
    }
   

    cacheLookup = *cacheHead;
    
    while(cacheLookup != NULL)
    {
	sigRefFound = 0;
	
	if(sigSeq != cacheLookup->obj.db_sig_id)
	{
	    sigSeq = cacheLookup->obj.db_sig_id;
	    databasemaxSeq = 0;
	    memset(sigRefArr,'\0',MAX_REF_OBJ);
	}
	
	if(dbSignatureReferenceLookup(&cacheLookup->obj,tempCache,&rNode,1))
	{
	    if( (cacheLookup->obj.ref_seq != rNode->obj.ref_seq))
	    {
		cacheLookup->obj.ref_seq = rNode->obj.ref_seq;
		
		if(cacheLookup->obj.ref_seq > MAX_REF_OBJ)
		{
		    FatalError("[%s()], can't process reference_sequence of [%d] for signature [%d] reference [%d] \n",
			       __FUNCTION__,
			       cacheLookup->obj.ref_seq,
			       cacheLookup->obj.db_sig_id,
			       cacheLookup->obj.db_ref_id);
		}
		    

		sigRefArr[cacheLookup->obj.ref_seq] = 1;
		
		if(databasemaxSeq < cacheLookup->obj.ref_seq)
		{
		    databasemaxSeq = cacheLookup->obj.ref_seq;
		}
	    }
	    cacheLookup->flag ^=(CACHE_BOTH | CACHE_INTERNAL_ONLY);
	}
	else
	{
	    /* Validate against value in database */
	    cCheck = tempCache;
	    
	    while(cCheck != NULL)
            {
		if( (cCheck->obj.db_sig_id == cacheLookup->obj.db_sig_id) &&
		    (cCheck->obj.db_ref_id == cacheLookup->obj.db_ref_id))
                {

		    cacheLookup->obj.ref_seq = cCheck->obj.ref_seq;

		    if(cacheLookup->obj.ref_seq > MAX_REF_OBJ)
		    {
			FatalError("[%s()], can't process reference_sequence of [%d] for signature [%d] reference [%d] \n",
				   __FUNCTION__,
				   cacheLookup->obj.ref_seq,
				   cacheLookup->obj.db_sig_id,
				   cacheLookup->obj.db_ref_id);
		    }
		    

		    sigRefArr[cacheLookup->obj.ref_seq] = 1;
		    sigRefFound = 1;

		    if(databasemaxSeq < cacheLookup->obj.ref_seq)
		    {
			databasemaxSeq = cacheLookup->obj.ref_seq;
			break;
		    }
                }
		
                cCheck = cCheck->next;
            }
	    
	    if(!sigRefFound)
	    {
		if(sigRefArr[cacheLookup->obj.ref_seq])
		{
		    cacheLookup->obj.ref_seq = (databasemaxSeq + 1);
		    
		    if(cacheLookup->obj.ref_seq > MAX_REF_OBJ)
		    {
			FatalError("[%s()], can't process reference_sequence of [%d] for signature [%d] reference [%d] \n",
				   __FUNCTION__,
				   cacheLookup->obj.ref_seq,
				   cacheLookup->obj.db_sig_id,
				   cacheLookup->obj.db_ref_id);
		    }

		    
		    databasemaxSeq =  cacheLookup->obj.ref_seq;
		    sigRefArr[cacheLookup->obj.ref_seq] = 1;
		}
		else
		{
		    if(cacheLookup->obj.ref_seq > MAX_REF_OBJ)
                    {
                        FatalError("[%s()], can't process reference_sequence of [%d] for signature [%d] reference [%d] \n",
                                   __FUNCTION__,
                                   cacheLookup->obj.ref_seq,
                                   cacheLookup->obj.db_sig_id,
                                   cacheLookup->obj.db_ref_id);
                    }
		    
		    sigRefArr[cacheLookup->obj.ref_seq] = 1;
		    
		    if(databasemaxSeq < cacheLookup->obj.ref_seq)
                    {
                        databasemaxSeq = cacheLookup->obj.ref_seq;
                     }
		}
	    }
	}
	
	cacheLookup = cacheLookup->next;
    }
    
    
    while(tempCache != NULL)
    {
	tNode = tempCache->next;
	free(tempCache);
	tempCache = tNode;
    }
    return 0;
    
f_err:
    while(tempCache != NULL)
    {
	tNode = tempCache->next;
	free(tempCache);
	tempCache = tNode;
    }
    return 1;

}


/** 
 *  Populate the sig_reference table with record that are not present in the database.
 * 
 * @note  Transaction isolation is done at row level to prevent possible race condition with an other starting process
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignatureReferencePopulateDatabase(DatabaseData *data,cacheSignatureReferenceObj *cacheHead)
{
    u_int32_t row_validate = 0;

    if( (data == NULL))
    {
        /* XXX */
        return 1;
    }
    
    if(cacheHead == NULL)
    {
	/* Do nothing */
	return 0;
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    
    
    while(cacheHead != NULL)
    {
        if(cacheHead->flag & CACHE_INTERNAL_ONLY)
        {
	    row_validate = 0;
#if DEBUG
            inserted_sigref_object_count++;
#endif

	    DatabaseCleanInsert(data);
            if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
                               SQL_INSERT_SIGREF,
                               cacheHead->obj.db_ref_id,
                               cacheHead->obj.db_sig_id,
                               cacheHead->obj.ref_seq)) != SNORT_SNPRINTF_SUCCESS)
	    {
                /* XXX */
                //goto TransactionFail;
		goto f_exit;
            }

	    DatabaseCleanSelect(data);
            if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                               SQL_SELECT_SPECIFIC_SIGREF,
                               cacheHead->obj.db_ref_id,
                               cacheHead->obj.db_sig_id,
                               cacheHead->obj.ref_seq)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
                /* XXX */
                //goto TransactionFail;
		goto f_exit;
            }
	    
	    /* Prevent race.. */
	    usleep(100);
	    
	    if(Select(data->SQL_SELECT,data,&row_validate))
            {
		/* Entry was not found */
		if(row_validate == 0)
		{
		    BeginTransaction(data);
		    
		    if(Insert(data->SQL_INSERT,data,1))
		    {
			/* XXX */
			goto TransactionFail;
		    }
		    
		    row_validate = 0;
		    
		    if(Select(data->SQL_SELECT,data,&row_validate))
		    {
			/* XXX */
			goto TransactionFail;
		    }
		    
		    if(row_validate != cacheHead->obj.db_ref_id)
		    {
			/* XXX */
			LogMessage("[%s()]: Couldn't validate insertion of values inserted INSERTED[%u], RECEIVED[%u] this is inconsistance and we quit.\n",
				   __FUNCTION__,
				   cacheHead->obj.db_ref_id,
				   row_validate);
			
			goto TransactionFail;
		    }
		    
		    CommitTransaction(data);
		}
	    }
	    
	    if(cacheHead->flag & CACHE_INTERNAL_ONLY)
	    {
		cacheHead->flag ^=(CACHE_INTERNAL_ONLY | CACHE_BOTH);
	    }
	    
        }
	cacheHead = cacheHead->next;
	
    }
    


    return 0;
    
TransactionFail:
    RollbackTransaction(data);
f_exit:
    return 1;
}


/** 
 * Wrapper function for signature reference cache synchronization
 * 
 * @param data 
 * @param cacheHead 
 * @param cacheSigHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SigRefSynchronize(DatabaseData *data,cacheSignatureReferenceObj **cacheHead,cacheSignatureObj *cacheSigHead)
{
    
    //cacheSignatureReferenceObj *SystemCacheElemPtr = NULL;
    dbSignatureReferenceObj *dbSigRefArray = NULL;
    
    u_int32_t array_length = 0;
    
    
    if( (data == NULL) ||
	(cacheHead == NULL) ||
	(cacheSigHead == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (GenerateSigRef(cacheHead,cacheSigHead)))
    {
	/* XXX */
	return 1;
    }
    
    //Pull from the db
    if( (SignatureReferencePullDataStore(data,&dbSigRefArray,&array_length)))
    {
	/* XXX */
        LogMessage("SignatureReferencePullDataStore failed \n");
	return 1;
    }

#if DEBUG
    db_sigref_object_count=array_length;
#endif
    
    if( array_length > 0 )
    {
        if( (SignatureReferenceCacheUpdateDBid(dbSigRefArray,
					       array_length,
					       cacheHead,
					       data->mc.cacheSignatureHead,
					       data->mc.cacheSystemHead)))
        {
	    if( dbSigRefArray != NULL)
            {
                free(dbSigRefArray);
                dbSigRefArray = NULL;
                array_length = 0;
            }
	    
            LogMessage("[%s()], Call to SignatureReferenceCacheUpdateDBid() failed \n",
                       __FUNCTION__);
            return 1;
        }
	
        if(dbSigRefArray != NULL)
        {
            free(dbSigRefArray);
            dbSigRefArray = NULL;
        }
        array_length = 0;
    }
    
    if( (SignatureReferencePopulateDatabase(data,*cacheHead)))
    {
	/* XXX */
	return 1;
    }
    
    //Ze done.
    return 0;
}
/***********************************************************************************************SIGREF API*/


/** 
 * Entry point function that convert existing cache to a form used by the spo_database
 * (only initialize with internal data)
 * 
 * @param bc 
 * @param data 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ConvertDefaultCache(Barnyard2Config *bc,DatabaseData *data)
{
    if((bc == NULL) ||
       (data == NULL))
    {
	/* XXX */
	FatalError("database [%s()], received a NULL argument : Barnyard2Config [0x%x] or DatabaseData [0x%x]  \n",
		   __FUNCTION__,
		   bc,
		   data);
    }
    
    if( (ConvertClassificationCache(&bc->classifications,&data->mc,data)))
    {
	/* XXX */
	return 1;
    }
    
    if( (ConvertSignatureCache(BcGetSigNodeHead(),&data->mc,data)))
    {
	/* XXX */
	return 1;
    }
    
    return 0;
}


/** 
 * Flush caches.
 * bye bye my love
 * 
 * @param data 
 */
void MasterCacheFlush(DatabaseData *data,u_int32_t flushFlag)
{

    cacheSignatureObj *MCcacheSignature;
    cacheClassificationObj *MCcacheClassification;
    cacheSignatureReferenceObj *MCcacheSigReference;
    cacheReferenceObj *MCcacheReference;
    cacheSystemObj *MCcacheSystem;
    
    void *holder;
    void *holder2;

    if(data == NULL)
    {
	/* XXX */
	return ;
    }


    /* Just clean the array's. */
    if( (flushFlag & CACHE_FLUSH_SIGREF) &&
	(!(flushFlag & CACHE_FLUSH_SIGNATURE)) &&
	(data->mc.cacheSignatureHead != NULL))
    {
	MCcacheSignature = data->mc.cacheSignatureHead;

        while( MCcacheSignature != NULL)
        {
	    MCcacheSignature->obj.ref_count = 0;
	    memset(MCcacheSignature->obj.ref,'\0',(sizeof(cacheReferenceObj *) * MAX_REF_OBJ));
	    MCcacheSignature= MCcacheSignature->next;
	}
    }
    
    if( (data->mc.cacheSignatureHead != NULL) &&
	(flushFlag & CACHE_FLUSH_SIGNATURE))
    {
	MCcacheSignature = data->mc.cacheSignatureHead;
	
	while( MCcacheSignature != NULL)
	{
	    holder = (void *)MCcacheSignature->next;
	    free(MCcacheSignature);
	    MCcacheSignature = (cacheSignatureObj *)holder;	
	}
	
	data->mc.cacheSignatureHead = NULL;
    }
    



    if( (data->mc.cacheClassificationHead!= NULL) &&
	(flushFlag & CACHE_FLUSH_CLASSIFICATION))
    {
	MCcacheClassification = data->mc.cacheClassificationHead;
	
	while( MCcacheClassification != NULL)
	{
	    holder = (void *)MCcacheClassification->next;
	    free(MCcacheClassification);
	    MCcacheClassification = (cacheClassificationObj *)holder;	
	}
	
	data->mc.cacheClassificationHead = NULL;
    }


    if( ( data->mc.cacheSigReferenceHead != NULL) &&
	(flushFlag & CACHE_FLUSH_SIGREF))
    {
	MCcacheSigReference = data->mc.cacheSigReferenceHead;
	
	while( MCcacheSigReference!= NULL)
	{
	    holder = (void *)MCcacheSigReference->next;
	    free(MCcacheSigReference);
	    MCcacheSigReference	= (cacheSignatureReferenceObj *)holder;	
	}
	
	data->mc.cacheSigReferenceHead = NULL;
    }
    
    if( (data->mc.cacheSystemHead != NULL) &&
	(flushFlag & CACHE_FLUSH_SYSTEM_REF))
    {
	MCcacheSystem = data->mc.cacheSystemHead;
	
	while( MCcacheSystem != NULL)
	{
	    holder = (void *)MCcacheSystem->next;

	    if(MCcacheSystem->obj.refList != NULL)
	    {
		MCcacheReference = MCcacheSystem->obj.refList;
		
		while( MCcacheReference != NULL)
		{
		    holder2 = (void *)MCcacheReference->next;
		    free(MCcacheReference);
		    MCcacheReference = (cacheReferenceObj *)holder2;
		}
		
		MCcacheSystem->obj.refList = NULL;
		
	    }

	    free(MCcacheSystem);
	    MCcacheSystem = (cacheSystemObj *)holder;	
	}
	
	data->mc.cacheSystemHead = NULL;
    }
    
    return;
    
}



/** 
 * Synchronize caches (internal from files and cache from database
 * 
 * @param data 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t CacheSynchronize(DatabaseData *data)
{
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    //Classification Synchronize
    if( (ClassificationCacheSynchronize(data,&data->mc.cacheClassificationHead)))
    {
	/* XXX */
	LogMessage("[%s()], ClassificationCacheSynchronize() call failed. \n",
		   __FUNCTION__);
	return 1;
    }
    
    //Signature Synchronize
    if( (SignatureCacheSynchronize(data,&data->mc.cacheSignatureHead)))
    {
	/* XXX */
	LogMessage("[%s()]:, SignatureCacheSynchronize() call failed. \n",
		   __FUNCTION__);
	return 1;
    }
    
    
    //System Synchronize
    if(data->mc.cacheSystemHead != NULL)
    {
	if( (SystemCacheSynchronize(data,&data->mc.cacheSystemHead)))
	{
	    /* XXX */
	    LogMessage("[%s()]:, SystemCacheSyncronize() call failed. \n",
		       __FUNCTION__);
	    return 1;
	}
	
	if(!data->dbRH[data->dbtype_id].disablesigref)
	{
	    //SigRef Synchronize 
	    if( (SigRefSynchronize(data,&data->mc.cacheSigReferenceHead,data->mc.cacheSignatureHead)))
	    {
		/* XXX */
		LogMessage("[%s()]: SigRefSynchronize() call failed \n",
			   __FUNCTION__);
		return 1;
	    }
	}
    }
    else
    {
	LogMessage("\n[%s()],INFO: No system was found in cache (from signature map file), will not process or synchronize informations found in the database \n\n",__FUNCTION__);
    }
#if DEBUG

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"================================================"
			    "===============================\n"));
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()], sleeping 5 second so you can look at cache statistics \n",
			    __FUNCTION__));
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"================================================"
			    "===============================\n"));


    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Signature]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_signature_object_count,
			    db_signature_object_count,
			    inserted_signature_object_count));
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Classification]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_classification_object_count,
			    db_classification_object_count,
			    inserted_classification_object_count));

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[System]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_system_object_count,
			    db_system_object_count,
			    inserted_system_object_count));
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Reference]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_reference_object_count,
			    db_reference_object_count,
			    inserted_reference_object_count));
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Signature Reference]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_sigref_object_count,
			    db_sigref_object_count,
			    inserted_sigref_object_count));

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"================================================"
			    "===============================\n\n"));

    sleep(5);

#endif

    
    /* Since we do not need reference and sig_reference clear those cache (free memory) and clean signature reference list and count */
    MasterCacheFlush(data,CACHE_FLUSH_SYSTEM_REF|CACHE_FLUSH_SIGREF|CACHE_FLUSH_SIGREF);
    /* Since we do not need reference and sig_reference clear those cache (free memory) and clean signature reference list and count */
    
    
    return 0;
}


