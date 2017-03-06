package com.mc.account.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Wenyu
 * @since 2/11/17
 */
@RestController
public class AccountController {

    @RequestMapping("/api/ok")
    String isOk() {
        return "OK";
    }
}
