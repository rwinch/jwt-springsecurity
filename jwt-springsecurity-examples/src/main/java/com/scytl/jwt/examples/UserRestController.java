package com.scytl.jwt.examples;


import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserRestController {

    
    @Autowired
    private ApplicationContext applicationContext;

    @PostConstruct
    public void init() {
        System.out.println(" *** MainRestController.init with: " + applicationContext);
    }

    @RequestMapping(value = "/login", produces = "text/plain")
    public String login() {
        return "There is nothing special about login here, just use Authorization: Basic, or provide secure token.\n" +
            "For testing purposes you can use headers X-Username and X-Password instead of HTTP Basic Access Authentication.\n" +
            "THIS APPLIES TO ANY REQUEST protected by Spring Security (see filter-mapping).\n\n" +
            "Realize, please, that Authorization request (or the one with testing X-headers) must be POST, otherwise they are ignored.";
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout() {
        return "Logout invalidates token on server-side. It must come as a POST request with valid X-Auth-Token, URL is configured for MyAuthenticationFilter.";
    }

    @RequestMapping("/test")
    public String test() {
        // Spring Security dependency is unwanted in controller, typically some @Component (UserContext) hides it.
        // Not that we don't use Spring Security annotations anyway...
        return "SecurityContext: " + SecurityContextHolder.getContext();
    }


    @RequestMapping("/secure/service1")
    public String service1() {
        return "Any authorized user should have access.";
    }

    // Spring annotation virtually equivalent with @RolesAllowed - except for...
    // WARNING: @Secured by default works only with roles starting with ROLE_ prefix, see this for more:
    // http://bluefoot.info/howtos/spring-security-adding-a-custom-role-prefix/
    // I don't want to mess with RoleVoters - that's why ADMIN does NOT have access to this page
    @Secured({"ROLE_SPECIAL", "ADMIN"})
    @RequestMapping("/secure/special")
    public String special() {
        return "ROLE_SPECIAL users should have access.";
    }

    // Spring annotation that speaks SpEL!
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(value = "/secure/allusers", produces="text/plain", method=RequestMethod.POST)
    public String allUsers() {
        return "A list of all users";
    }
    
}
