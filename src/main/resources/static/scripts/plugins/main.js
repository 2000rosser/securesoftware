$(function () {
    $(".input-group .form-control").focus(function () {
        $(this).siblings('.input-group-prepend').children('.input-group-text').css('border-color', '#5e72e4')
        $(this).siblings('.input-group-prepend').children('.input-group-text').css('color', '#5e72e4')
        $(this).siblings('.input-group-addon').children('.input-group-text').css('border-color', '#5e72e4')
        $(this).siblings('.input-group-addon').children('.input-group-text').css('color', '#5e72e4')
    });

    $(".input-group .form-control").blur(function () {
        $(this).siblings('.input-group-prepend').children('.input-group-text').css('border-color', '#cad1d7')
        $(this).siblings('.input-group-prepend').children('.input-group-text').css('color', '#adb5bd')
        $(this).siblings('.input-group-addon').children('.input-group-text').css('border-color', '#cad1d7')
        $(this).siblings('.input-group-addon').children('.input-group-text').css('color', '#adb5bd')
    });
});