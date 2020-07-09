package org.launchcode.javawebdevtechjobsauthentication;

import org.launchcode.javawebdevtechjobsauthentication.controllers.AuthenticationController;
import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

public class AuthenticationFilter extends HandlerInterceptorAdapter {
    //whitelist variable containing the paths that can be accessed without a user session
    private static final List<String> whitelist = Arrays.asList("/login", "/register", "/logout", "/index", "/view");

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationController authenticationController;

    //preHandle method
    //override the inherited method of the same name
    //grab session information from the request object
    //query the session data for a user
    //if a user exists return true, otherwise redirect to the login page and return false

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {
        if (isWhitelisted(request.getRequestURI())) {
            return true;
        }
        HttpSession session = request.getSession();
        User user = authenticationController.getUserFromSession(session);

        if (user != null) {
            return true;
        }

        response.sendRedirect("/login");
        return false;
    }

    //method that checks a given path against the values in the whitelist
    //update preHandle (before looking for session and user status, add a conditional that checks the whitelist status of the current request object)

    private static boolean isWhitelisted(String path) {
        for (String pathRoot : whitelist) {
            if (path.startsWith(pathRoot)) {
                return true;
            }
        }
        return false;
    }

}
