/*
 *  blog.h
 *  
 *
 *  Created by zhou hongyu on 08-2-26.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */
#include <sys/types.h>

void InitializeBlog(const unsigned char *m_ip, const unsigned char *m_netmask,
				const unsigned char *m_netgate, const unsigned char *m_dns1);
				
void FillNetParameter(unsigned char ForFill[]);

unsigned char Alog(unsigned char BForAlog);

void Blog();