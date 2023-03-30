set(COMPONENT_SRCS
	"mqtt_mutual_auth.c"
	"r307.c"
)

#"r307.c"
#"r307.h"
	
set(COMPONENT_ADD_INCLUDEDIRS
	"."
	"${CMAKE_CURRENT_LIST_DIR}"
)

idf_component_register(
	SRCS 
		"${COMPONENT_SRCS}"
		
	INCLUDE_DIRS 
		${COMPONENT_ADD_INCLUDEDIRS}
)

spiffs_create_partition_image(storage ../spiffs FLASH_IN_PROJECT)