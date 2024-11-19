package com.example.apigateway.config;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class LoggingFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication())
                .switchIfEmpty(Mono.justOrEmpty(null))
                .flatMap(authentication -> {
                    if (authentication != null && authentication instanceof JwtAuthenticationToken) {
                        System.out.println("Request is valid: " + exchange.getRequest().getURI());
                    } else {
                        System.out.println("Request is invalid: " + exchange.getRequest().getURI());
                    }
                    return chain.filter(exchange);
                });
    }
}