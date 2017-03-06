package com.mc.security.token;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Wenyu
 * @since 3/5/17
 */
public class JwtAuthenticationRequestMatcher implements RequestMatcher {

    private OrRequestMatcher skippingMatcher;

    private RequestMatcher processingMatcher;

    public JwtAuthenticationRequestMatcher(List<String> pathToSkip, String processingPath) {

        List<RequestMatcher> matchers = pathToSkip.stream()
                .map(AntPathRequestMatcher::new)
                .collect(Collectors.toList());

        skippingMatcher = new OrRequestMatcher(matchers);
        processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return !skippingMatcher.matches(request) && processingMatcher.matches(request);
    }
}
