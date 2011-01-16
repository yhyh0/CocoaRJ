//
//  MainController.m
//  CocoaRJ
//
//  Created by Yin Hou on 6/2/09.
//  alanhoucts@Gmail.com
//  Copyright 2009 SCU. All rights reserved.
//
/*
 This file is part of CocoaRJ.
 
 CocoaRJ is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 CocoaRJ is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with CocoaRJ.  If not, see <http://www.gnu.org/licenses/>.
*/

#import "MainController.h"
#import "md5.h"
#import <Security/Authorization.h>
static AuthorizationRef authorizationRef;


@implementation MainController
@synthesize username, password, connect, disconnect, detail, retryCountButton, progressIndicator;


-(void)awakeFromNib{
	tokenMenu = [[NSMenu alloc] init];

	connectItem = [[NSMenuItem alloc] initWithTitle:@"Connect" action:@selector(connect:) keyEquivalent:@"c"];
	[connectItem setTarget:self];
	[tokenMenu addItem:connectItem];
	[self.progressIndicator setHidden:YES];
	
	childPID = -1;

	[disconnect setEnabled:NO];
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *user = [defaults stringForKey:@"Ruijie_username"];
	NSString *pass = [defaults stringForKey:@"Ruijie_password"];
	if (user == nil) user = @"";
	if (pass == nil) pass = @"";
	
	[username setStringValue:user];
	[password setStringValue:pass];
}
//int read (long,StringPtr,int);
//int write (long,StringPtr,int);
static OSStatus GetToolPath(CFStringRef bundleID, CFStringRef toolName, char *toolPath, size_t toolPathSize)
{
    OSStatus    err;
    CFBundleRef bundle;
    Boolean     success;
    CFURLRef    toolURL;
    
    assert(bundleID != NULL);
    assert(toolName != NULL);
    assert(toolPath != NULL);
    assert(toolPathSize > 0);
    
    toolURL = NULL;
    
    err = noErr;
    bundle = CFBundleGetBundleWithIdentifier(bundleID);
    if (bundle == NULL) {
        err = coreFoundationUnknownErr;
    }
    if (err == noErr) {
        toolURL = CFBundleCopyAuxiliaryExecutableURL(bundle, toolName);
        if (toolURL == NULL) {
            err = coreFoundationUnknownErr;
        }
    }
    if (err == noErr) {
        success = CFURLGetFileSystemRepresentation(toolURL, true, (UInt8 *) toolPath, toolPathSize);
        if ( ! success ) {
            err = coreFoundationUnknownErr;
        }
    }
    
    if (toolURL != NULL) {
        CFRelease(toolURL);
    }
    
    return err;
}


-(void)initAuthorization{
/*	OSStatus    junk;

	junk = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &gAuth);
    assert(junk == noErr);
    assert( (junk == noErr) == (gAuth != NULL) );
	
	BASSetDefaultRules(
					   gAuth, 
					   kSampleCommandSet, 
					   CFBundleGetIdentifier(CFBundleGetMainBundle()), 
					   CFSTR("SampleAuthorizationPrompts")
					   );
	*/
	OSStatus authStatus;
	authStatus = AuthorizationCreate (NULL, kAuthorizationEmptyEnvironment,
									kAuthorizationFlagDefaults, &authorizationRef);
	if(authStatus == errAuthorizationSuccess){
//		NSLog(@"AuthorizationCreateSuccess");
	}
	
	AuthorizationItem authorizationItem;
	
	authorizationItem.name = "edu.scu.CocoaRJ.rootRight";
	authorizationItem.valueLength = 0;
	authorizationItem.value = NULL;
	authorizationItem.flags = 0;
	
	AuthorizationRights authRights;
	authRights.count = 1;
	authRights.items = &authorizationItem;
	
	AuthorizationFlags authFlags;
	authFlags = kAuthorizationFlagDefaults |
	kAuthorizationFlagExtendRights |
	kAuthorizationFlagInteractionAllowed |
	kAuthorizationFlagPreAuthorize;
	authStatus = AuthorizationCopyRights (authorizationRef, &authRights,
										kAuthorizationEmptyEnvironment, authFlags, NULL);
	if(authStatus == errAuthorizationSuccess){
	//	NSLog(@"AuthorizationCopyRightsSuccess");
	}
	
	AuthorizationExternalForm externalAuthorizationRef;
	authStatus = AuthorizationMakeExternalForm (authorizationRef,
											  &externalAuthorizationRef);
	if(authStatus == errAuthorizationSuccess){
	//	NSLog(@"AuthorizationMakeExternalFormSuccess");
	}
	ruijieThread = [[NSThread alloc] initWithTarget:self selector:@selector(ruijieAuthThread:) object:nil];
	[ruijieThread start];
	[connect setEnabled:NO];
	[connectItem setTitle:@"Disconnect"];
	[connectItem setAction:@selector(disconnect:)];
//	connectItem = [[NSMenuItem alloc] initWithTitle:@"Disconnect" action:@selector(disconnect:) keyEquivalent:@"d"];
//	[tokenMenu itemChanged:connectItem];
	[disconnect setEnabled:YES];
	[self.progressIndicator setHidden:NO];
	[self.progressIndicator startAnimation:self];
}

-(void)ruijieAuthThread:(id)object{

	NSImage *myImage = [NSImage imageNamed: @"IconAqua"];
	[NSApp setApplicationIconImage: myImage];
	
	[detail setStringValue:@""];
	[detail setNeedsDisplay];

	char        helperToolPath[PATH_MAX];
	NSString *      bundleID;
	bundleID = [[NSBundle mainBundle] bundleIdentifier];
	OSStatus authStatus;
	OSStatus    retval;
	retval = GetToolPath((CFStringRef)bundleID, CFSTR("HelperTool"),  helperToolPath,  sizeof(helperToolPath));	
	
	AuthorizationFlags authFlags;
	authFlags = kAuthorizationFlagDefaults |
	kAuthorizationFlagExtendRights |
	kAuthorizationFlagInteractionAllowed |
	kAuthorizationFlagPreAuthorize;

	char *name = (char *)[[username stringValue] UTF8String];
	char *pass = (char *)[[password stringValue] UTF8String];
	char *retryCount = (char *)[[retryCountButton titleOfSelectedItem] UTF8String];
	char *myArguments[] = { name, pass, "en0", retryCount, NULL };
	FILE *myCommunicationsPipe = NULL;
//	char myReadBuffer[128];
	
	authFlags = kAuthorizationFlagDefaults;
	
	// add md5 check
	//	ae07009948e7bc82fb04268ce297d0c1
	unsigned char md5check[0x10]={0xae, 0x07, 0x00, 0x99, 0x48, 0xe7, 0xbc, 0x82, 0xfb, 0x04, 0x26, 0x8c, 0xe2, 0x97, 0xd0, 0xc1};
	unsigned char temp[0x20];
	unsigned char md5_result[0x10];
	char _md5path[PATH_MAX];
	//NSString *	bundleID;
	//bundleID = [[NSBundle mainBundle] bundleIdentifier];
	
	GetToolPath((CFStringRef)bundleID, CFSTR("HelperTool"), _md5path, sizeof(_md5path));
	
	FILE* htfile = fopen(_md5path, "rb");
	
	fseek(htfile, 0x612, 0);
	fread(temp, 0x20, 1, htfile);
	
	MD5_CTX context;
	MD5Init(&context);
	
	MD5Update(&context, temp, 0x20);
	MD5Final(md5_result, &context);
	int i;
//	printf("md5:");
	for (i = 0;i < 0x10; i++){
		//printf("%x ", md5_result[i]);
		if (md5check[i]!=md5_result[i]) {
			NSImage *myImage = [NSImage imageNamed: @"IconError"];
			[NSApp setApplicationIconImage: myImage];
			[detail setStringValue:@"HeplerTool MD5 check error!!"];
			[detail setNeedsDisplay];

			[NSThread exit];
		}
			
	}
//	printf("\n");
	
	
	//NSLog(@"md5=%s",md5_result);
	// end md5 check
	
	authStatus = AuthorizationExecuteWithPrivileges                  
	(authorizationRef, helperToolPath, authFlags, myArguments,
	 &myCommunicationsPipe);
	
	NSMutableString *detailString = [[NSMutableString alloc] init];
	if (authStatus == errAuthorizationSuccess){

		char	thisLine[1024];
		BOOL success;
		int tmpLong;
		char tmpStr[255];
		
		do {
		//	NSLog(@"before fgets");
			success = (fgets(thisLine, sizeof(thisLine), myCommunicationsPipe) != NULL);
		//	NSLog(@"after fgets");

			if ( ! success ) {
				authStatus = errState;
		//		NSLog(@"fgets !success");
				AuthorizationFree (authorizationRef, kAuthorizationFlagDefaults);   
				[connect setEnabled:YES];
				[connectItem setTitle:@"Connect"];
				[connectItem setAction:@selector(connect:)];
				[disconnect setEnabled:NO];
				[self.progressIndicator stopAnimation:self];
				[self.progressIndicator setHidden:YES];
				if(childPID != -1){
					const char* command = [[NSString stringWithFormat:@"kill -15 %d", childPID] cString];
					system(command);
					childPID = -1;
				}
				fclose(myCommunicationsPipe);
				[NSThread exit];
				break;
			}

			// Look for the success token and terminate with no error in that case.
		//	NSLog(@"line!");
			if (strcmp(thisLine, "echo\n") == 0) {
		//		assert(authStatus == noErr);
		//		break;
			}
			else if(strstr(thisLine, "error") != NULL){
				NSImage *myImage = [NSImage imageNamed: @"IconError"];
				[NSApp setApplicationIconImage: myImage];
				[detailString appendString:[NSString stringWithCString:thisLine encoding:NSUTF8StringEncoding]];
				[detail setStringValue:detailString];
				[detail setNeedsDisplay];

			}
			else if(sscanf(thisLine, "pid<<<%ld>>>pid\n", &tmpLong) == 1){
				childPID = (pid_t) tmpLong;
			//	NSLog(@"GET pid<<<%ld>>>pid\n", childPID);
			}
			else if(strcmp(thisLine, "Have Fun :)\n") == 0){
				[self.progressIndicator stopAnimation:self];
				[self.progressIndicator setHidden:YES];
				NSImage *myImage = [NSImage imageNamed: @"IconYES"];
				[NSApp setApplicationIconImage: myImage];
				[detailString appendString:[NSString stringWithCString:thisLine encoding:NSUTF8StringEncoding]];
				[detail setStringValue:detailString];
				[detail setNeedsDisplay];

			}
			else{
				[detailString appendString:[NSString stringWithCString:thisLine encoding:NSUTF8StringEncoding]];
				[detail setStringValue:detailString];
				[detail setNeedsDisplay];

			}
			
			if([ruijieThread isCancelled]){
				NSLog(@"NSThread exit");
				AuthorizationFree (authorizationRef, kAuthorizationFlagDefaults);   
				[connect setEnabled:YES];
				[connectItem setTitle:@"Connect"];
				[connectItem setAction:@selector(connect:)];
				[disconnect setEnabled:NO];
				[self.progressIndicator stopAnimation:self];
				[self.progressIndicator setHidden:YES];

				if(childPID != -1){
					const char* command = [[NSString stringWithFormat:@"kill -15 %d", childPID] cString];
					system(command);
					childPID = -1;
				}
				[detail setStringValue:@"Logged out."];
				[detail setNeedsDisplay];
				NSImage *myImage = [NSImage imageNamed: @"IconAqua"];
				[NSApp setApplicationIconImage: myImage];
				fclose(myCommunicationsPipe);
				[NSThread exit];
			}
		} while (true);
		
/*
		 for(;;)
		{
			int bytesRead = read (fileno (myCommunicationsPipe), myReadBuffer, sizeof (myReadBuffer));
	//		NSLog(@"read = %d", bytesRead);
			//	if (bytesRead < 1) break;
			//		NSLog(@"[NSString stringWithUTF8String:myReadBuffer] = %@",[NSString stringWithCString:myReadBuffer encoding:NSUTF8StringEncoding]);
			write (fileno (stdout), myReadBuffer, bytesRead);
			[detailString appendString:[[NSString stringWithCString:myReadBuffer encoding:NSUTF8StringEncoding] substringToIndex:bytesRead]];
			[detail setStringValue:detailString];

		}
		 */
		
	}
	[connect setEnabled:YES];
	[connectItem setTitle:@"Connect"];
	[connectItem setAction:@selector(connect:)];
	[disconnect setEnabled:NO];
	[self.progressIndicator stopAnimation:self];
	[self.progressIndicator setHidden:YES];
}
-(IBAction)process{
	/*
	OSStatus        err;
    BASFailCode     failCode;
    NSString *      bundleID;
    NSDictionary *  request;
    CFDictionaryRef response;
	
    response = NULL;
    
    // Create our request.  Note that NSDictionary is toll-free bridged to CFDictionary, so 
    // we can use an NSDictionary as our request.
    
    request = [NSDictionary dictionaryWithObjectsAndKeys:@kRuijieCommand, @kBASCommandKey, nil];
    assert(request != NULL);
    
    bundleID = [[NSBundle mainBundle] bundleIdentifier];
    assert(bundleID != NULL);

		
    // Execute it.
/*
	err = BASExecuteRequestInHelperTool(
										gAuth, 
										kSampleCommandSet, 
										(CFStringRef) bundleID, 
										(CFDictionaryRef) request, 
										&response
										);
	*/
	/*
	 NSLog(@"BASExecuteRequestInHelperTool==%d", err);
    
    // If it failed, try to recover.
	err = noErr;
    if ( (err == noErr) && (err != userCanceledErr) ) {
        int alertResult;
        
        failCode = BASDiagnoseFailure(gAuth, (CFStringRef) bundleID);
		
        // At this point we tell the user that something has gone wrong and that we need 
        // to authorize in order to fix it.  Ideally we'd use failCode to describe the type of 
        // error to the user.
		
        alertResult = NSRunAlertPanel(@"Needs Install", @"BAS needs to install", @"Install", @"Cancel", NULL);
        
        if ( alertResult == NSAlertDefaultReturn ) {
            // Try to fix things.
			NSLog(@"alertResult == NSAlertDefaultReturn");

            err = BASFixFailure(gAuth, (CFStringRef) bundleID, CFSTR("LibInstall"), CFSTR("HelperTool"), failCode);

            // If the fix went OK, retry the request.
            
            if (err == noErr) {
                err = BASExecuteRequestInHelperTool(
													gAuth, 
													kSampleCommandSet, 
													(CFStringRef) bundleID, 
													(CFDictionaryRef) request, 
													&response
													);
            }
        } else {
            err = userCanceledErr;
			NSLog(@"userCanceledErr");

        }
    }
    
    // If all of the above went OK, it means that the IPC to the helper tool worked.  We 
    // now have to check the response dictionary to see if the command's execution within 
    // the helper tool was successful.
	NSLog(@"oldErr=%d",err);

    
    if (err == noErr) {
        err = BASGetErrorFromResponse(response);
		NSLog(@"BASGetErrorFromResponse=%d",err);
    }
    
    // Log our results.
    
    if (err == noErr) {
        [textView insertText:
		 [NSString stringWithFormat:@"RUID = %@, EUID=%@\n", 
		  [(NSDictionary *)response objectForKey:@kSampleGetUIDsResponseRUID],
		  [(NSDictionary *)response objectForKey:@kSampleGetUIDsResponseEUID]
		  ]
		 ];
    } else {
        [textView insertText:
		 [NSString stringWithFormat:@"Failed with error %ld.\n", (long) err]
		 ];
    }
    
		NSString *temp = [NSString stringWithFormat:@"RUID = %@, EUID=%@\n", 
						   [(NSDictionary *)response objectForKey:@kSampleRuijieResponseRUID],
						   [(NSDictionary *)response objectForKey:@kSampleRuijieResponseEUID]
						  ];
		NSLog(@"kSampleGetUIDsResponseEUID = %@", temp);
	}
    if (response != NULL) {
        CFRelease(response);
    }
	*/
}

-(IBAction)connect:(id)sender{
	   
//	[self process];
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	
    if ([[username stringValue] isEqualToString:@""]) {
		[[NSAlert alertWithMessageText:@"Alert" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Username or password is blank!"] runModal];
		return;
        [defaults removeObjectForKey:@"Ruijie_username"];
    } else {
        [defaults setObject:[username stringValue] forKey:@"Ruijie_username"];
    }

	if ([[password stringValue] isEqualToString:@""]) {
		[[NSAlert alertWithMessageText:@"Alert" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Username or password is blank!"] runModal];
		return;
        [defaults removeObjectForKey:@"Ruijie_password"];
    } else {
        [defaults setObject:[password stringValue] forKey:@"Ruijie_password"];
    }
	
	[self initAuthorization];

	
}
-(IBAction)disconnect:(id)sender{
	[self.progressIndicator setHidden:NO];
	[self.progressIndicator startAnimation:self];
	[ruijieThread cancel];

}

- (NSMenu *)applicationDockMenu:(NSApplication *)sender{
	
//	[tokenMenu addItem:[NSMenuItem separatorItem]];
	//[tokenMenu removeItem:connectItem];
	return tokenMenu;
}

-(void)applicationWillTerminate:(NSNotification *)notification{
	NSImage *myImage = [NSImage imageNamed: @"IconAqua"];
	[NSApp setApplicationIconImage: myImage];
	if(childPID > 0){
		const char* command = [[NSString stringWithFormat:@"kill -15 %d", childPID] cString];
		system(command);
		childPID = -1;
	}
	[ruijieThread cancel];
//	NSLog(@"applicationWillTerminate");
}

@end
