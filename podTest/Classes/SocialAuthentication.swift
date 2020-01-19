//
//  SocialAuthentication.swift
//  AceTradies
//
//  Created by Kasun Sandeep on 11/13/19.
//  Copyright © 2019 ElegantMedia. All rights reserved.
//

import UIKit
import GoogleSignIn
import FBSDKCoreKit
import FBSDKLoginKit
import AuthenticationServices
import TwitterKit

enum SocialAuthenticationType: String, Codable {
    case google = "GOOGLE"
    case facebook = "FACEBOOK"
    case twitter = "TWITTER"
    case apple = "APPLE"
}

struct UserStruct :Codable {
    var id: String
    var type: SocialAuthenticationType
    var name: String
    var email: String
}


typealias SocialAuthenticationActionHandler = (_ status: Bool, _ user: UserStruct?) -> ()

class SocialAuthentication: NSObject {
    //Facebook variables
    var fbLoginManager : LoginManager = LoginManager()
    
    //Apple variables
//    let appleIDProvider = ASAuthorizationAppleIDProvider()
//    var authorizationController: ASAuthorizationController?
    
    var callback: SocialAuthenticationActionHandler?
    
    static var shared :SocialAuthentication = {
        let model = SocialAuthentication()
        
        model.config()
        model.fbLoginManager = LoginManager()
        
        return model
    }()
    
    //MARK:- Config
    func config() {
        //Google config
        GIDSignIn.sharedInstance().delegate = self
        
        //Apple config
//        let request = appleIDProvider.createRequest()
//        request.requestedScopes = [.fullName, .email]
//        SocialAuthentication.shared.authorizationController = ASAuthorizationController(authorizationRequests: [request])
//        SocialAuthentication.shared.authorizationController?.delegate = self
    }
    
    //MARK:- Login
    func login(_ type: SocialAuthenticationType, viewController vc: UIViewController, callback: @escaping SocialAuthenticationActionHandler) {
        SocialAuthentication.shared.callback = callback
        
        switch type {
        case .google:
            GIDSignIn.sharedInstance().signIn()
            break
        case .facebook:
            SocialAuthentication.shared.loginFacebook(vc: vc)
            break
        case .twitter:
            loginTwitter(vc: vc)
            break
        case .apple:
//            SocialAuthentication.shared.authorizationController?.performRequests()
            if #available(iOS 13.0, *) {
                let request = ASAuthorizationAppleIDProvider().createRequest()
                request.requestedScopes = [.fullName, .email]
                
                let authorizationController: ASAuthorizationController = ASAuthorizationController(authorizationRequests: [request])
                authorizationController.delegate = self
                authorizationController.performRequests()
            } else {
                // Fallback on earlier versions
            }
            break
        }
    }
    
    var resetData :Void {
        get {
            logoutFacebook()
            SocialAuthentication.shared = SocialAuthentication()
            SocialAuthentication.shared.config()
        }
    }
}

//MARK:- Google
extension SocialAuthentication: GIDSignInDelegate {
    func sign(_ signIn: GIDSignIn!, didSignInFor user: GIDGoogleUser?, withError error: Error?) {
        if error != nil, user?.authentication == nil {
            SocialAuthentication.shared.callback?(false, nil)
            return
        }
        
        SocialAuthentication.shared.callback?(true, UserStruct(id: user?.authentication.idToken ?? "", type: .google, name: user?.profile.name ?? "", email: user?.profile.email ?? ""))
    }
    
    func sign(_ signIn: GIDSignIn!, didDisconnectWith user: GIDGoogleUser!, withError error: Error!) {
        SocialAuthentication.shared.callback?(false, nil)
    }
}

//MARK:- Facebook
extension SocialAuthentication {
    func loginFacebook(vc: UIViewController) {
        self.logoutFacebook()
        
        fbLoginManager.logIn(permissions: ["email"], from: vc) { (result, error) -> Void in
          if (error == nil){
            // if user cancel the login
            if (result?.isCancelled)! {
                SocialAuthentication.shared.callback?(false, nil)
                return
            }
            
            SocialAuthentication.shared.callback?(true, UserStruct(id: AccessToken.current?.tokenString ?? "", type: .facebook, name: "", email: ""))
          } else {
            SocialAuthentication.shared.callback?(false, nil)
          }
        }
    }
    
    func syncFacebookUserData(_ callback: @escaping SocialAuthenticationActionHandler) {
        let request = GraphRequest(graphPath: "me", parameters: ["fields":"email,name"], tokenString: AccessToken.current?.tokenString, version: nil, httpMethod: .get)
        request.start { (connection, data, error) in
            guard let result = data else {
                SocialAuthentication.shared.callback?(false, nil)
                return
            }
            
            do {
                guard let jsonData = try? JSONSerialization.data(withJSONObject:result) else {
                    SocialAuthentication.shared.callback?(false, nil)
                    return
                }
                
                var user = try JSONDecoder().decode(UserStruct.self, from: jsonData)
                user.type = .facebook
                
                SocialAuthentication.shared.callback?(true, user)
            } catch let parsingError {
                print("Error", parsingError)
                SocialAuthentication.shared.callback?(false, nil)
            }
        }
    }
    
    func logoutFacebook() {
        fbLoginManager.logOut()
    }
}

//MARK:- Twitter
extension SocialAuthentication {
    func loginTwitter(vc: UIViewController) {
        TWTRTwitter.sharedInstance().logIn(with: vc, completion: { (session, error) in
            if (error == nil){
                SocialAuthentication.shared.callback?(true, UserStruct(id: session?.authToken ?? "", type: .twitter, name: session?.userName ?? "", email: ""))
            } else {
                SocialAuthentication.shared.callback?(false, nil)
            }
        })
    }
}

@available(iOS 13.0, *)
extension SocialAuthentication: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let appleIDCredential = authorization.credential as?  ASAuthorizationAppleIDCredential else {
            SocialAuthentication.shared.callback?(false, nil)
            return
        }

        SocialAuthentication.shared.callback?(true, UserStruct(id: appleIDCredential.user, type: .apple, name: appleIDCredential.fullName?.givenName ?? "", email: appleIDCredential.email ?? ""))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        SocialAuthentication.shared.callback?(false, nil)
    }
}
