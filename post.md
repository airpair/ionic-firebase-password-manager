There are many password managers on the market right now, all of which may or may not truly keep your passwords safe.  This puts us in a position where maybe it is best to just create your own password manager so you know how your data is being stored and where it is being sent.

In this particular tutorial we are going to see how to encrypt password data in JavaScript using the very strong AES cipher.  To keep our passwords synchronized across all our devices and platforms we are going to bind all our data to [Firebase](https://www.firebase.com).  The base behind our mobile applications will be [AngularJS](https://angularjs.org/) with [Ionic Framework](http://www.ionicframework.com).

## Creating a New Ionic Framework Project

### The Prerequisites

* The latest [Firebase JavaScript](https://cdn.firebase.com/js/client/2.2.2/firebase.js) library
* The latest [AngularFire AngularJS](https://cdn.firebase.com/libs/angularfire/1.0.0/angularfire.min.js) library
* A Mac with Xcode installed if building for iOS
* NPM, [Apache Cordova](http://cordova.apache.org/), Ionic, and Android installed and configured

### Creating Our Project

To start things off, we're going to create a fresh Ionic project using our Terminal (Mac and Linux) or Command Prompt (Windows):

```bash,linenums=true
ionic start PasswordApp blank
cd PasswordApp
ionic platform add android
ionic platform add ios
```

Remember, if you're not using a Mac with Xcode installed, you cannot add and build for the iOS platform.

At this point we're left with a new Android and iOS project using the Ionic Framework **blank** template.

### Adding Our Libraries

In our Ionic project's **www/index.html** we need to add all the various prerequisite libraries.  The file's `<head>` should look something like the following:

```markup,linenums=true
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="initial-scale=1, maximum-scale=1, user-scalable=no, width=device-width">
    <title></title>
    <link href="lib/ionic/css/ionic.css" rel="stylesheet">
    <link href="css/style.css" rel="stylesheet">
    <script src="lib/ionic/js/ionic.bundle.js"></script>
    <script src="cordova.js"></script>
    <script src="js/forge.min.js"></script>
    <script src="js/firebase.js"></script>
    <script src="js/angularfire.min.js"></script>
    <script src="js/app.js"></script>
</head>
```

Wait!  Where did **js/forge.min.js** come from?  Well, we cannot just download that file so we need to build it in the next step.

## Building the Forge Library

If you've been keeping up with my tutorials you'll remember that I've done a segment on [AES ciphers with JavaScript](https://blog.nraboy.com/2014/10/implement-aes-strength-encryption-javascript/) using the Forge library.  I played around with a few different crypto libraries for JavaScript, and Forge was by far the best.

### Downloading From GitHub

Unlike many JavaScript library projects on GitHub, Forge does not offer a minified release / distribution file for including in your browser based application.  This means we need to download the project and do it ourself.

We have two options when it comes to obtaining the project.  We can either download the latest master branch [archive file](https://github.com/digitalbazaar/forge/archive/master.zip), or clone the project with Git:

```
git clone https://github.com/digitalbazaar/forge.git
```

Both methods will accomplish the same thing.

### Installing The Dependencies

Because we're working with Ionic Framework and Apache Cordova, I'm confident at this point you already have the Node Package Manager (NPM) installed.

With the downloaded Forge project as your current working directory your Terminal or Command Prompt run the following command to install all the necessary NPM dependencies:

```
npm install
```

They'll be downloaded locally to the project rather than globally on your machine.

### Minifying For Use

With all the dependencies installed, it is now time to build a single minified file for use with our project.  Make sure the Forge project is still the current working directory in your Terminal or Command Prompt and run the following:

```
npm run minify
```

This will execute the minify script creating **js/forge.min.js** for use in our Ionic Framework project.

## Preparing Our JavaScript File

For simplicity, we are going to be doing all custom JavaScript coding in our **www/js/app.js** file.  It will contain all our controllers, factories, and prototypes.

### Naming Our AngularJS Module

For cleanliness, we are going to give our AngularJS module a name.

```javascript
var passwordApp = angular.module("starter", ["ionic"]);
```

In this case we've named our module `passwordApp` and it will be used for all controllers and factories in our application.

### Getting Firebase Started

We're not quite ready to talk about Firebase, but we are at a point where it would be a good idea to initialize it.  At the top of your **www/js/app.js** file, outside any AngularJS code, you want to add the following line:

```javascript
var fb = new Firebase("https://INSTANCE_ID_HERE.firebaseio.com/");
```

Of course you need to replace **INSTANCE_ID_HERE** with your personal Firebase instance.  By setting it globally, it will load before AngularJS and can be used throughout your application.

We also need to add `firebase` to our AngularJS module.  In the end it will look something like this:

```javascript
var passwordApp = angular.module("starter", ["ionic", "firebase"]);
```

## Creating a Cipher Factory for Encryption and Decryption

### The Factory For Cipher Text

The `$cipherFactory` will accomplish two things.  Using the Forge library, there will be an `encrypt(message, password)` function and a `decrypt(cipherText, password, salt, iv, options)` function.

Inside your **www/js/app.js** file, add the following AngularJS factory:

```javascript,linenums=true
passwordApp.factory("$cipherFactory", function() {

    return {

        encrypt: function(message, password) {
            var salt = forge.random.getBytesSync(128);
            var key = forge.pkcs5.pbkdf2(password, salt, 4, 16);
            var iv = forge.random.getBytesSync(16);
            var cipher = forge.cipher.createCipher('AES-CBC', key);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(message));
            cipher.finish();
            var cipherText = forge.util.encode64(cipher.output.getBytes());
            return {cipher_text: cipherText, salt: forge.util.encode64(salt), iv: forge.util.encode64(iv)};
        },

        decrypt: function(cipherText, password, salt, iv, options) {
            var key = forge.pkcs5.pbkdf2(password, forge.util.decode64(salt), 4, 16);
            var decipher = forge.cipher.createDecipher('AES-CBC', key);
            decipher.start({iv: forge.util.decode64(iv)});
            decipher.update(forge.util.createBuffer(forge.util.decode64(cipherText)));
            decipher.finish();
            if(options !== undefined && options.hasOwnProperty("output") && options.output === "hex") {
                return decipher.output.toHex();
            } else {
                return decipher.output.toString();
            }
        }

    };

});
```

Encrypting will leave us with some cipher text as well as the salt and initialization vector used during encryption.  All this information is required to decrypt.

### Our Strategy for Safe Storage

The idea behind our application is simple.  All data will be encrypted using AES and can only be accessed with a master password.

The master password will never be saved in our application and an incorrect master password will only give junk data.

So how are we going to accomplish this?  When the user creates a master password in our application, instead of saving the master password in our application, we are going to encrypt the static string **Authenticated** and store the cipher text it produces in our application.  When the user wishes to sign into the application we will decrypt the **Authenticated** cipher text using the entered password.  If it is anything but **Authenticated** when decrypted, we'll reject the user's access.

### Making Some Helper Prototypes

The cipher factory is complete, but in order to stick with our safe storage strategy we need to create a few string prototypes.  For example when decrypting our **Authenticated** string, if the password is incorrect then the data will error when converting into a string.  To avoid this we can do comparisons against a hexadecimal value:

```javascript,linenums=true
String.prototype.toHex = function() {
    var buffer = forge.util.createBuffer(this.toString());
    return buffer.toHex();
}
```
We'll also need a prototype for generating a unique hash from a string value:

```javascript,linenums=true
String.prototype.toSHA1 = function() {
    var md = forge.md.sha1.create();
    md.update(this);
    return md.digest().toHex();
}
```

Both these string prototypes should go at the very bottom of your **www/js/app.js** file.

## Using the AngularJS UI-Router

Our application is going to have several different screens:

* Unlock the application
* Register a new master password
* Sign into Firebase
* Viewing password categories
* Viewing passwords in a category
* Creating a password
* Viewing a password

To accomplish different screens or views in an AngularJS application we will be using the UI-Router since it is already bundled with Ionic Framework.  If you're familiar with my other tutorials, you might have already seen a [previous demonstration](https://blog.nraboy.com/2014/11/using-ui-router-navigate-ionicframework/) that I've done.

### Preparing Our States

With the AngularJS UI-Router, each view or screen is considered a state.  In order to use we must configure the routes and the controllers associated with them.  In your Ionic project's **www/js/app.js** file, let's add the following chunk of code which will represent the states for each of our screens:

```javascript,linenums=true
passwordApp.config(function($stateProvider, $urlRouterProvider) {
    $stateProvider
        .state("locked", {
            url: "/locked",
            templateUrl: "templates/locked.html",
            controller: "VaultController",
            cache: false
        })
        .state("createvault", {
            url: "/createvault",
            templateUrl: "templates/create_vault.html",
            controller: "VaultController"
        })
        .state("firebase", {
            url: "/firebase",
            templateUrl: "templates/firebase.html",
            controller: "FirebaseController"
        })
        .state("categories", {
            url: "/categories/:masterPassword",
            templateUrl: "templates/categories.html",
            controller: "CategoryController"
        })
        .state("passwords", {
            url: "/passwords/:categoryId/:masterPassword",
            templateUrl: "templates/password_list.html",
            controller: "PasswordController",
            cache: false
        })
        .state("newpassword", {
            url: "/newpassword/:categoryId/:masterPassword",
            templateUrl: "templates/password_new.html",
            controller: "PasswordController"
        })
        .state("viewpassword", {
            url: "/viewpassword/:categoryId/:masterPassword/:passwordId",
            templateUrl: "templates/password_view.html",
            controller: "PasswordController"
        });
    $urlRouterProvider.otherwise('/locked');
});
```

### Creating Our Views

We've just configured all of the routing information for our states so it is now time to set up our view templates.  Essentially these are the HTML pages that will represent each of our screens.

The first step is to prepare our Ionic project's **www/index.html** file to use UI states.  This is easy and can be accomplished in just a few lines.  Navigate to the `<ion-pane>` lines and replace them with the following:

```markup,linenums=true
<ion-pane>
    <ion-nav-bar class="bar-stable"></ion-nav-bar>
    <ion-nav-view></ion-nav-view>
</ion-pane>
```

Time to go through the process of designing each of our views.  Brace yourself.  Our templates are going to be very simplistic.  Feel free to be fancier in your view design.

Create and open the file called **www/templates/locked.html** and add the following code:

```markup,linenums=true
<ion-view title="Unlock Vault" ng-init="init()">
    <ion-content>
        <div class="padding-left padding-top padding-right">
            <h1>Welcome</h1>
        </div>
        <div>
            <div class="list list-inset">
                <label class="item item-input">
                    <input ng-model="masterpassword" type="password" placeholder="Master Password" />
                </label>
            </div>
            <div class="padding-left padding-right">
                <div class="button-bar">
                    <a class="button" ng-click="unlock(masterpassword)">Unlock</a>
                    <a class="button" ng-click="reset()">Reset</a>
                </div>
            </div>
        </div>
    </ion-content>
</ion-view>
```

Now create and open the file called **www/templates/create_vault.html** and add the following code:

```markup,linenums=true
<ion-view title="Create Vault" ng-init="init()">
    <ion-content>
        <div class="padding-left padding-top padding-right">
            <h1>Welcome</h1>
        </div>
        <div>
            <div class="list list-inset">
                <label class="item item-input">
                    <input ng-model="masterpassword" type="password" placeholder="Master Password" />
                </label>
            </div>
            <div class="padding-left padding-right">
                <div class="button-bar">
                    <a class="button" ng-click="create(masterpassword)">Create</a>
                </div>
            </div>
        </div>
    </ion-content>
</ion-view>

```

You've created the views for creating and using a master password.  Now lets move onto our list screens.  The first list will be in a file called **www/templates/categories.html** and will be a list of categories like below:

```markup,linenums=true
<ion-view title="Categories" ng-init="list()">
    <ion-nav-buttons side="right">
        <button class="right button button-icon icon ion-plus" ng-click="add()"></button>
    </ion-nav-buttons>
    <ion-content>
        <ion-list>
            <ion-item ng-repeat="item in categories" ui-sref="passwords({categoryId: item.id, masterPassword: masterPassword})">
                {{item.category}}
            </ion-item>
        </ion-list>
    </ion-content>
</ion-view>
```

The second list will be in a file called **www/templates/password_list.html** and will be a list of passwords that reside in a particular category:

```markup,linenums=true
<ion-view title="Passwords" ng-init="list()">
    <ion-nav-buttons side="left">
        <button class="left button button-icon icon ion-arrow-left-c" ng-click="back()"></button>
    </ion-nav-buttons>
    <ion-nav-buttons side="right">
        <button class="right button button-icon icon ion-plus" ui-sref="newpassword({categoryId: categoryId, masterPassword: masterPassword})"></button>
    </ion-nav-buttons>
    <ion-content>
        <ion-list>
            <ion-item ng-repeat="item in passwords" ui-sref="viewpassword({categoryId: categoryId, masterPassword: masterPassword, passwordId: item.id})">
                {{item.password.title}}
            </ion-item>
        </ion-list>
    </ion-content>
</ion-view>
```

So now we need three more views.  One for creating new passwords, one for viewing passwords, and then finally a screen forcing users to hook up Firebase.  Starting with creating new passwords, create and open **www/templates/password_new.html** and add the following code:

```markup,linenums=true
<ion-view title="Password">
    <ion-nav-buttons side="left">
        <button class="left button button-icon icon ion-arrow-left-c" ng-click="back()"></button>
    </ion-nav-buttons>
    <ion-content>
        <div>
            <div class="list list-inset">
                <label class="item item-input">
                    <input ng-model="title" type="text" placeholder="Title" />
                </label>
                <label class="item item-input">
                    <input ng-model="username" type="text" placeholder="Username" />
                </label>
                <label class="item item-input">
                    <input ng-model="password" type="password" placeholder="Password" />
                </label>
            </div>
            <div class="padding-left padding-right">
                <div class="button-bar">
                    <a class="button" ng-click="save(title, username, password)">Save</a>
                </div>
            </div>
        </div>
    </ion-content>
</ion-view>
```

You can see from the above template that our passwords are only going to consist of a title, username, and password.  Feel free to get more complex that I did.

The next view, **www/templates/password_view.html**, will be similar to the new password screen, but this time we'll only be showing the data.  For simplicity purposes, the password will be revealed upon load.

```markup,linenums=true
<ion-view title="Password" ng-init="view()">
    <ion-nav-buttons side="left">
        <button class="left button button-icon icon ion-arrow-left-c" ng-click="back()"></button>
    </ion-nav-buttons>
    <ion-content>
        <div class="list list-inset">
            <ion-item>
                {{password.title}}
            </ion-item>
            <ion-item>
                {{password.username}}
            </ion-item>
            <ion-item>
                {{password.password}}
            </ion-item>
        </div>
    </ion-content>
</ion-view>
```

Of course you can fancy it up and expose the password only upon request.

The final view we're going to make is for our Firebase login.  Create and open **www/templates/firebase.html** and add the following code:

```markup,linenums=true
<ion-view title="Firebase Login">
    <ion-content>
        <div>
            <div class="list list-inset">
                <label class="item item-input">
                    <input ng-model="username" type="text" placeholder="Username" />
                </label>
                <label class="item item-input">
                    <input ng-model="password" type="password" placeholder="Password" />
                </label>
            </div>
            <div class="padding-left padding-right">
                <div class="button-bar">
                    <a class="button" ng-click="login(username, password)">Login</a>
                    <a class="button" ng-click="register(username, password)">Register</a>
                </div>
            </div>
        </div>
    </ion-content>
</ion-view>
```

Wew! Finally we've created all the views that will go with our application.

## Configuring Our Firebase Instance

### Defining Permissions

Like my previous tutorial regarding building a [Firebase Todo List](https://blog.nraboy.com/2014/12/syncing-data-firebase-using-ionic-framework/), we're going to be using the same permission strategy:

```json
{
    "rules": {
        "users": {
            ".write": true,
            "$uid": {
                ".read": "auth != null && auth.uid == $uid"
            }
        }
    }
}
```

Everyone will be able to write to the `users` node (create a new account), but only authorized users will be able to read data.  In this case data will be the users own passwords.  You can paste the JSON rules in the **Security & Rules** section of the Firebase dashboard.

### Allowing For Account Creation

In the **Login & Auth** section of the Firebase dashboard, we must enable **Email & Password** authentication.  There are other types of authentication, but for this particular tutorial we're going to focus on email and password based.

Enabling this will allow people to register new accounts and create a unique `simplelogin:x` user key in our NoSQL data structure where `x` is an auto incrementing numeric value.

## Syncing Our Passwords With Firebase

### The Structure of Our Data

The data stored will be of very strict formatting.  It will of course be JSON, but it will look like the following:

```json
{
    "categories": {
        "unique_category_id_here": {
            "category": {
                "cipher_text": "",
                "salt": "",
                "iv": ""
            },
            "passwords": {
                "unique_password_id_here": {
                    "cipher_text": "",
                    "salt": "",
                    "iv": ""
                }
            }
        }
    },
    "masterPassword": {
        "cipher_text": "",
        "salt": "",
        "iv": ""
    }
}
```

Both categories and passwords in a category are encrypted offering maximum data protection.  Each category will be hashed to receive a unique id and each password in a category will be hashed to receive a unique id.  However, a password is not a single field of text.  It is a serialized object that is then encrypted.

For example, lets say we have the following password object:

```json
{
    "title": "",
    "username": "",
    "password": ""
}
```

We would then pass the object through JavaScript's `JSON.stringify()` method and then encrypt the string.

## Making Our Controllers To Handle View Logic

Time for the logic that makes everything count.  In this particular application, multiple views can be part of a controller.  For example anything that has to do with the master password (unlocking and creating) will be in our `VaultController`.  Anything that has to do with Firebase login or registering will be in our `FirebaseController`.  Anything that has to do with password categories will be in our `CategoryController`.  Finally anything that has to do with listing, creating or viewing passwords will end up in our `PasswordController`.

### The Vault Controller

The logic behind the `VaultController` controller will be as follows:

* Make sure any screens that follow don't remember the vault screens so the back button won't return people.
* Check if we are authenticated with Firebase
    * If we are authenticated then bind our users node
    * If we are not authenticated then redirect to the Firebase login
* If we are unlocking with a master password, attempt to decrypt the stored master with the entered master password
    * If the hex values match then navigate to the categories screen while passing the master.  We never store the master password in local storage.
* If we are creating a master password, use the entered password to encrypt a string of our choosing to compare against when trying to unlock.
* If we are resetting, then clear all information from Firebase and start fresh.

```javascript,linenums=true
passwordApp.controller("VaultController", function($scope, $state, $ionicHistory, $firebaseObject, $cipherFactory) {

    $ionicHistory.nextViewOptions({
        disableAnimate: true,
        disableBack: true
    });

    var fbAuth = fb.getAuth();
    if(fbAuth) {
        var userReference = fb.child("users/" + fbAuth.uid);
        var syncObject = $firebaseObject(userReference);
        syncObject.$bindTo($scope, "data");
    } else {
        $state.go("firebase");
    }

    $scope.unlock = function(masterPassword) {
        syncObject.$loaded().then(function() {
            var decipherPhrase = $cipherFactory.decrypt($scope.data.masterPassword.cipher_text, masterPassword, $scope.data.masterPassword.salt, $scope.data.masterPassword.iv, {output: "hex"});
            if(decipherPhrase === "Authenticated".toHex()) {
                $state.go("categories", {masterPassword: masterPassword});
            }
        });
    }

    $scope.create = function(masterPassword) {
        syncObject.$loaded().then(function() {
            userReference.child("masterPassword").set($cipherFactory.encrypt("Authenticated", masterPassword), function(error) {
                $state.go("locked");
            });
        });
    }

    $scope.reset = function() {
        userReference.remove(function(error) {
            if(error) {
                console.error("ERROR: " + error);
            } else {
                $state.go("createvault");
            }
        });
    }

});
```

I can't stress this enough.  Don't store your master password.  Your best bet is to encrypt a string or hash it, then store it.

### The Firebase Login Controller

The logic behind the `FirebaseController` is as follows:

* Clear the history stack after navigating away so users cannot return by hitting back
* If user clicks sign in they will be validated against Firebase and directed to the lock screen
* If the user clicks register they will have their account created, signed in, and then directed to the create master password screen for first time use

```javascript,linenums=true
passwordApp.controller("FirebaseController", function($scope, $state, $ionicHistory, $firebaseAuth) {

    $ionicHistory.nextViewOptions({
        disableAnimate: true,
        disableBack: true
    });

    var fbAuth = $firebaseAuth(fb);

    $scope.login = function(username, password) {
        fbAuth.$authWithPassword({
            email: username,
            password: password
        }).then(function(authData) {
            $state.go("locked");
        }).catch(function(error) {
            console.error("ERROR: " + error);
        });
    }

    $scope.register = function(username, password) {
        fbAuth.$createUser({email: username, password: password}).then(function(userData) {
            return fbAuth.$authWithPassword({
                email: username,
                password: password
            });
        }).then(function(authData) {
            $state.go("createvault");
        }).catch(function(error) {
            console.error("ERROR: " + error);
        });
    }

});
```

Firebase stores sign in information on the device so that you can later make use of the `getAuth()` functions to see if you're currently authenticated.

### The Categories Controller

The logic for the `CategoryController` will be as follows:

* Check if we are authenticated with Firebase
    * If we are authenticated then bind our users node
    * If we are not authenticated then redirect to the Firebase login
* The list function will get all hashed category ids and then push each category into an array that can be repeated through with AngularJS.  All pushed values will have been first decrypted.
* The add function will hash the category name for use as an id value then store the encrypted category in Firebase while finally pushing the decrypted value into the list.

```javascript,linenums=true
passwordApp.controller("CategoryController", function($scope, $ionicPopup, $firebaseObject, $stateParams, $cipherFactory) {

    $scope.masterPassword = $stateParams.masterPassword;
    $scope.categories = [];

    var fbAuth = fb.getAuth();
    if(fbAuth) {
        var categoriesReference = fb.child("users/" + fbAuth.uid);
        var syncObject = $firebaseObject(categoriesReference);
        syncObject.$bindTo($scope, "data");
    } else {
        $state.go("firebase");
    }

    $scope.list = function() {
        syncObject.$loaded().then(function() {
            for(var key in $scope.data.categories) {
                if($scope.data.categories.hasOwnProperty(key)) {
                    $scope.categories.push({
                        id: key,
                        category: $cipherFactory.decrypt($scope.data.categories[key].category.cipher_text, $stateParams.masterPassword, $scope.data.categories[key].category.salt, $scope.data.categories[key].category.iv)
                    });
                }
            }
        });
    }

    $scope.add = function() {
        $ionicPopup.prompt({
            title: 'Enter a new category',
            inputType: 'text'
        })
        .then(function(result) {
            if(result !== undefined) {
                if($scope.data.categories === undefined) {
                    $scope.data.categories = {};
                }
                if($scope.data.categories[result.toSHA1()] === undefined) {
                    $scope.data.categories[result.toSHA1()] = {
                        category: $cipherFactory.encrypt(result, $stateParams.masterPassword),
                        passwords: {}
                    };
                    $scope.categories.push({
                        id: result.toSHA1(),
                        category: result
                    });
                }
            } else {
                console.log("Action not completed");
            }
        });
    }

});
```

### The Passwords Controller

Time for our final controller.  The `PasswordController` accomplishes the most in comparison to the others.

The logic is as follows:

* Check if we are authenticated with Firebase
    * If we are authenticated then bind our users node
    * If we are not authenticated then redirect to the Firebase login
* List all passwords in a category in if viewing from the list screen.
    * Decrypt every password for viewing in the list.  Only titles will be displayed
    * Decrypted passwords will be pushed into an array compatible with `ng-repeat`.
* If trying to view a password, find only that node and decrypt it
* If trying to save a password, serialize the password and then encrypt the string for storage in Firebase.
    * Unique password ids are created by hashing the serialized string

```javascript,linenums=true
passwordApp.controller("PasswordController", function($scope, $stateParams, $firebaseObject, $state, $cipherFactory, $ionicHistory) {

    $scope.masterPassword = $stateParams.masterPassword;
    $scope.categoryId = $stateParams.categoryId;
    $scope.passwords = [];

    var fbAuth = fb.getAuth();
    if(fbAuth) {
        var categoryReference = fb.child("users/" + fbAuth.uid + "/categories/" + $stateParams.categoryId);
        var passwordsReference = fb.child("users/" + fbAuth.uid + "/categories/" + $stateParams.categoryId + "/passwords");
        var syncObject = $firebaseObject(categoryReference);
        syncObject.$bindTo($scope, "data");
    } else {
        $state.go("firebase");
    }

    $scope.list = function() {
        syncObject.$loaded().then(function() {
            var encryptedPasswords = $scope.data.passwords;
            for(var key in encryptedPasswords) {
                if(encryptedPasswords.hasOwnProperty(key)) {
                    $scope.passwords.push({
                        id: key,
                        password: JSON.parse($cipherFactory.decrypt(encryptedPasswords[key].cipher_text, $stateParams.masterPassword, encryptedPasswords[key].salt, encryptedPasswords[key].iv))
                    });
                }
            }
        });
    }

    $scope.view = function() {
        syncObject.$loaded().then(function() {
            var encryptedPassword = $scope.data.passwords[$stateParams.passwordId];
            $scope.password = JSON.parse($cipherFactory.decrypt(encryptedPassword.cipher_text, $stateParams.masterPassword, encryptedPassword.salt, encryptedPassword.iv));
        });
    }

    $scope.save = function(title, username, password) {
        var passwordObject = {
            title: title,
            username: username,
            password: password
        };
        syncObject.$loaded().then(function() {
            passwordsReference.child(JSON.stringify(passwordObject).toSHA1()).set($cipherFactory.encrypt(JSON.stringify(passwordObject), $stateParams.masterPassword), function(ref) {
                $state.go("passwords", $stateParams);
            });
        });
    }

    $scope.back = function() {
        $ionicHistory.goBack();
    }

});
```

## Locking Our App When Losing Focus

The app may not always be in focus.  Maybe you've exited or put it in the background.  We want to make sure users are forced to re-enter their password when regaining focus in order to maintain security.

```javascript,linenums=true
passwordApp.run(function($ionicPlatform, $state) {
    $ionicPlatform.ready(function() {
        if(window.cordova && window.cordova.plugins.Keyboard) {
            cordova.plugins.Keyboard.hideKeyboardAccessoryBar(true);
        }
        if(window.StatusBar) {
            StatusBar.styleDefault();
        }
    });
    document.addEventListener("resume", function() {
        $state.go("locked", {}, {location: "replace"});
    }, false);
});
```

Notice in particular in the above code the event listener for resume.  When the application resumes focus we will be navigated to the locked screen just as if we were opening the application fresh.

Finally inside the `VaultController` we need to add:

```javascript
$ionicHistory.clearHistory();
```

This will go above the `$ionicHistory.nextViewOptions`.  It is responsible for clearing our history stack when we resume the application.

## Properly Testing The App

### Using the Web Browser

In plenty of my [tutorials](https://blog.nraboy.com/2015/02/properly-testing-ionic-framework-mobile-application/), tweets, and forum comments I say not to test your mobile application in a web browser.  I still stand by this, but if you insist, this particular app should work fine in the browser because it makes use of no native device plugins.  Our mobile app consists of only CSS, JavaScript, and HTML.

Go ahead and run the following from your Command Prompt or Terminal if you wish to test via a web browser:

```
ionic serve
```

Then in your browser navigate to the URL and crack open your JavaScript console.  It won't give you a true experience, but you'll get a general idea on if the application is functioning.

### Using a Device or Simulator

To test this application on your device or simulator, run the following in your Command Prompt or Terminal:

```
ionic build android
adb install -r platforms/android/ant-build/CordovaApp-debug.apk
```

The above will get you going on Android.  If you wish to track down errors and view the logs, you can use the Android Debug Bridge (ADB) like so:

```
adb logcat
```

More information on this can be seen in one of my [other tutorials](https://blog.nraboy.com/2014/12/debugging-android-source-code-adb/) on the topic.

## Conclusion

You've just made a lite competitor to established password managers such as 1Password, LastPass and KeePass using [Ionic Framework](http://www.ionicframework.com) as your foundation and [Firebase](http://www.firebase.com) as your cloud solution.  The data stored in the application and in the Firebase cloud is protected with an AES cipher for maximum security.

This project can be forked on [GitHub](https://github.com/nraboy/ionic-cipher-safe-app) if you wish to see it all put together.
