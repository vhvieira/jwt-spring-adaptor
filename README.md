# jwt-spring-adaptor
Adaptor to easily implement JWT security, using internal and external authentication (including LDAP) on any SpringBoot project.

### How to use the jwt-spring-adaptor
The component that was create in the POC as security-core should be named as jwt-adapter.
It should be used as a abstraction for JWT implementation easily, not requiring complex configuration. 



## Dependencies required:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency> <br>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency> <br>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-cache</artifactId>
</dependency> <br>
<dependency>
    <groupId>org.springframework.ldap</groupId>
    <artifactId>spring-ldap-core</artifactId>
</dependency> <br>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-ldap</artifactId>
</dependency> <br>
```

##How to create a security configuration

Like any other SpringBoot application you need to create a configuration class and extend from WebSecurityConfigurerAdapter. <br>
But instead of creating the whole configuration on your own, all you need to do is create this class, and inside this class using inner class extending from the jwt-adaptor base classes and provide the configuration you want, as in the example:

```java
@EnableWebSecurity
@Configuration
public class ExampleJWTAdaptorConfiguration extends WebSecurityConfigurerAdapter {
 
    @Configuration
    @Order(1)
    public class BasicAuthSecurityAdapter extends BaseBasicAuthToInternalJWTConfig {
        /**
         * Adding configuration for basic authentication
         */
        public BasicAuthSecurityAdapter() {
 
            super(new BasicAuthToInternalJWTConfiguration());
        }
 
    }
 
    @Configuration
    @Order(2)
    public class InternalJWTSecurityAdapter extends BaseInternalJWTConfig {
 
        /**
         * Adding configuration for internal JWT
         */
        public InternalJWTSecurityAdapter() {
            super(new InternalJWTConfiguration());
        }
 
    }
 
    @Configuration
    @Order(3)
    public class ExternalJWTSecurityAdapter extends BaseExternalJWTConfig {
        /**
         * Adding configuration for external JWT
         */
        public ExternalJWTSecurityAdapter() {
            super(new ExternalJWTConfiguration());
        }
    }
}
```


##Understanding the Base Classes:

This initial version of jwt-adaptor contains 3 base classes do be used in our project:

- **BaseBasicAuthToInternalJWTConfig** Which is the class to implement your login, using LDAP, In-Memory Credentials or a custom username/password validation, as for example a database login. This configuration is required if you plan to create internal tokens in our application, since this will be used to authenticate the user while tokens will be used for authorization, for more details on how to configure the BaseBasicAuthToInternalJWTConfig please go the specific session.


- **BaseInternalJWTConfig** This is the adapter class that will secure all your endpoints if you want use internal JWT in your applications. This adaptor contains the logic to secure the endpoints with a common pattern in their URL and validate specific permissions that will be stored in the token, for more details on how to configure the InternalJWTSecurityAdapter please go the specific session. Note: This adapter depends on the BaseBasicAuthToInternalJWTConfig 


- **ExternalJWTSecurityAdapter** This is the adapter class that will secure all your endpoints if you want use external JWT in your applications. This adaptor contains the logic to secure the endpoints with a common pattern in their URL and validates the token using an external URL that should be private, so only users that have access to that external application will have access to your applications and you can map different external application to different user roles, for more details on how to configure the ExternalJWTSecurityAdapter please go the specific session.

## JWT Spring Adaptor implementation example
Please referer to this project for a working implementation of JWT using JWT Spring Adaptor.
[Example project](https://github.com/vhvieira/jwt-spring-adaptor-example)
