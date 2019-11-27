package com.javierrodriguez.springsecurityexample.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/private")
public class PrivateController{

@GetMapping
public String getMessage(){
    return "Hola mundo desde privado";
 }
}