$(function(){
  if ($('#form_create_account').size() == 1) {
    $('#form_create_account').bind('submit',function(){
      if ($('#password').val() != $('#password_confirm').val() ||
          $('#password').val() == '' ||
          $('#password_confirm').val() == ''
         ) {
        $('.control-group.password').addClass('error');
        return false;
      }
      else {
        $('.password-group.password').removeClass('error');
        return true;
      }
    });
  }
});
