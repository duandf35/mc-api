package com.mc.security.utils;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Wenyu
 * @since 3/5/17
 */
public final class WebUtils {

    public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";

    public static final String JWT_TOKEN_HEADER_PREFIX = "Bearer-";

    public static final String AUTH_USERNAME_KEY = "username";

    public static final String AUTH_PASSWORD_KEY = "password";

    // http://stackoverflow.com/questions/17478731/whats-the-point-of-the-x-requested-with-header
    // | Without CORS it is not possible to add X-Requested-With to a cross domain XHR request.
    private static final String AJAX_HEADER_KEY = "X-Requested-With";

    private static final String AJAX_HEADER_VALUE = "XMLHttpRequest";

    public static boolean isAjax(HttpServletRequest request) {
        return request.getHeader(AJAX_HEADER_KEY).contains(AJAX_HEADER_VALUE);
    }

    private WebUtils() {

    }
}
