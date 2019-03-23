<?php

use Respect\Validation\Validator as v;
$greek = 'ς ε ρ τ υ θ ι ο π α σ δ φ γ η ξ κ λ ζ χ ψ ω β ν μ Ε Ρ Τ Υ Θ Ι Ο Π Α Σ Δ Φ Γ Η Ξ Κ Λ Ζ Χ Ψ Ω Β Ν Μ έ ύ ί ό ά ή ώ ';
$usernameValidator = v::alnum($greek)->noWhitespace()->length(1, 32)->notBlank();//Validates alphanumeric characters from a-Z and 0-9 and without whitespace ,required
$nameValidator = v::stringType()->alnum($greek)->noWhitespace()->length(1, 32)->notBlank();//Validates string characters from a-Z and 0-9 and without whitespace ,required
$surnameValidator = v::stringType()->alnum($greek)->noWhitespace()->length(1, 32)->notBlank(); //Validates string characters from a-Z and 0-9 and without whitespace, required
$dateValidator = v::date('Y-m-d')->between('1950-01-01', '2000-01-01')->notBlank(); //Date bust be between 1/1/1950 to 1/1/2000,required
$trainingDateValidator = v::optional(v::date('Y-m-d')->between('2010-01-01', 'now')); //Training Date bust be between 1/1/2010 to now
$emailValidator = v::email()->notBlank()->alnum('@ .'); //Validates email format,required
$mobileNumberValidator = v::positive()->notBlank()->length(10,10);//Validates mobile number format ,required
$mobile2NumberValidator = v::optional(v::positive()->length(10,10));//Validates mobile number format
$addressValidator=v::optional(v::alnum($greek));//Validates alphanumeric characters from a-Z and 0-9
$locationValidator = v::stringType()->alnum($greek)->notBlank();// validates location to be string and not blank,required
$passwordValidator = v::stringType()->alnum($greek)->notBlank()->length(10,10); 
$defibrillatordateValidator=v::optional(v::date('Y-m-d')->between('2019-01-01', 'now'))->notBlank();
$patientDateOfBirth=v::intType()->min(1950)->max(2010);
$adminTypeValidator=v::alnum($greek)->stringType()->noWhitespace();
$RFIDValidator = v::intVal()->notBlank();

