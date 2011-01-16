//
//  MainController.h
//  CocoaRJ
//
//  Created by HouYin on 6/2/09.
//  Copyright 2009 SCU. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface MainController : NSObject {

	IBOutlet NSTextField *username;
	IBOutlet NSTextField *detail;
	IBOutlet NSProgressIndicator *progressIndicator;
	IBOutlet NSPopUpButton *retryCountButton;
	IBOutlet NSSecureTextField *password;
	IBOutlet NSButton *connect,*disconnect;
	NSMenuItem *connectItem, *disconnectItem;
	NSMenu *tokenMenu;
	NSThread *ruijieThread;
	int childPID;
	
}
-(void)initAuthorization;
-(IBAction)connect:(id)sender;
-(IBAction)disconnect:(id)sender;

@property(assign, nonatomic) NSProgressIndicator *progressIndicator;
@property(assign, nonatomic) NSTextField *detail;
@property(assign, nonatomic) NSPopUpButton *retryCountButton;
@property(assign, nonatomic) NSTextField *username;
@property(assign, nonatomic) NSSecureTextField *password;
@property(assign, nonatomic) NSButton *connect, *disconnect;

@end
