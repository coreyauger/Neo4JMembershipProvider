Neo4JMembershipProvider
=======================

asp.net Neo4J Membership Provider


## Dependencies
Neo4J Graph Database >= v 2.0.0 (Make sure it has label support)

Neo4JClient [https://www.nuget.org/packages/Neo4jClient](https://www.nuget.org/packages/Neo4jClient).
NOTE: this package is auto installed as a dependency when you use NuGet


## Install
NuGet package [https://www.nuget.org/packages/Neo4JMembershipProvider/](https://www.nuget.org/packages/Neo4JMembershipProvider/)

This is a step by step install for a new MVC application.

First thing to do is to make sure that you have the latest NuGet installed in your Visual Studio.
Again, make sure it is the latest version.

![ScreenShot](http://www.coreyauger.com/images/neo/1.jpg)

At this point make sure that you have Neo4J up and running and that you can connect to it.  Assuming you have Neo4J installed on your localhost you should be able to connect via your web browser with the address.
```
http://localhost:7474
```
If you have everything up and running you should see a screen similar to this one.
![ScreenShot](http://www.coreyauger.com/images/neo/3.jpg)

Create a new MVC 3/4 web application.  Once you are looking at the project files, right click on your refrences and choose "Manage NuGet Packages.."

This will open the NuGet Modal.
Select "Online" from your list of sources on the left hand side.
Next you can search for "Neo4JMembershipProvider" in the top right search menu.

Once you see the package in the main list.  Click the install button.

Verify that the package installed by looking for a green checkmark next to the package.  See image as refrence
![ScreenShot](http://www.coreyauger.com/images/neo/2.jpg)

Now we have to make a few changes to the configuration of our application.

First off we will need to modify our web.config file to include the following lines
```xml
<configuration>
  
  ...
  
 <connectionStrings>
    <add name="DefaultConnection" connectionString="http://localhost:7474/db/data" providerName="Nextwave.Neo4J.Connector.Neo4JClient" />
  </connectionStrings>
  <appSettings>
    
    ...
  
    <add key="enableSimpleMembership" value="false" />
    <add key="autoFormsAuthentication" value="false" />
  </appSettings>
  <system.web>
    
    ...
  
    <roleManager enabled="true" />
    <machineKey validationKey="C50B3C89CB21F4F1422FE158A5B42D0E8DB8CB6CDA1742572A48722401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE" decryptionKey="8A9BE8FD22AF6979E7D20198CFEA50DD3D3799C77AF2B722" validation="SHA1" />
    <membership defaultProvider="Neo4JMembershipProvider" userIsOnlineTimeWindow="15">
      <providers>
        <clear />
        <add name="Neo4JMembershipProvider" type="Nextwave.Neo4J.Membership.Neo4JMembershipProvider" connectionStringName="DefaultConnection" applicationName="Nextwave" enablePasswordRetrieval="true" enablePasswordReset="true" requiresQuestionAndAnswer="false" requiresUniqueEmail="true" passwordFormat="Hashed" />
      </providers>
    </membership>
    
    ...
    
</configuration>
```
I have also included an image with the highlighted changes.  
NOTE: that your connection string may need to change <localhost> to point to your db location
![ScreenShot](http://www.coreyauger.com/images/neo/4.jpg)

The last thing you need to do is to modify your "InitializeSimpleMembershipAttribute.cs"
This is located in your <MVC Projects>/filters/InitializeSimpleMembershipAttribute.cs

Make the following code changes
```CS
  [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
  public sealed class InitializeSimpleMembershipAttribute : ActionFilterAttribute
  {
      private static SimpleMembershipInitializer _initializer;
      private static object _initializerLock = new object();
      private static bool _isInitialized;

      public override void OnActionExecuting(ActionExecutingContext filterContext)
      {
          // Ensure ASP.NET Simple Membership is initialized only once per app start
          LazyInitializer.EnsureInitialized(ref _initializer, ref _isInitialized, ref _initializerLock);
      }

      private class SimpleMembershipInitializer
      {
          public SimpleMembershipInitializer()
          {
              try
              {
                  WebSecurity.InitializeDatabaseConnection("DefaultConnection", "User", "Id", "UserName", autoCreateTables: false);
              }
              catch (Exception ex)
              {
                  throw new InvalidOperationException("Something is wrong", ex);
              }
          }
      }
  }
```

That should be all you need.  
You will now be able to start your application and regester / login

Your users will be nodes in neo4J with the "User" label.

So for example you could list all your users with the following Cypher
```
MATCH u:User RETURN u;
```

## Finally 
My solution has only undergone a very small amount of testing.  
However, if you have any trouble please contact me and I will be glad to help.  

Thanks... and Enjoy the power of your new graph db :)



[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/coreyauger/neo4jmembershipprovider/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

