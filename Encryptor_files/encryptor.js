var encryptorState = true;//Encryption

var switchRoles = function(){
	if(encryptorState){
		//Change to decryption:
		$('#inputBoxDesc').text('Text to Decrypt');
		$('#outputBoxDesc').text('Decrypted Text');
		$('#submitButton').text('Decrypt');
		$('#passwordReenterBox').attr('disabled','disabled');
		$('#passwordReenterBox').val('');
	}else{
		//Change to encryption:
		$('#inputBoxDesc').text('Text to Encrypt');
		$('#outputBoxDesc').text('Encrypted Text');
		$('#submitButton').text('Encrypt');
		$('#passwordReenterBox').removeAttr('disabled');
	}
	$('#outputBox').text('');
	encryptorState = !encryptorState;
}

var onSubmitButtonClick = function(){
	var inputText = $('#inputBox').val();
	var password = $('#passwordBox').val();
	var passwordReenter = $('#passwordReenterBox').val();
	var result;

	//If user's encrypting, do the 2 passwords match?
	if(encryptorState){
		if(password != passwordReenter){
			alert('Error: The passwords do not match');
			return;
		}
	}

	//Are we encryting or decrypting?
	if(encryptorState){
		result = CryptoJS.AES.encrypt(inputText, password);
	}else{
		result = CryptoJS.AES.decrypt(inputText, password).toString(CryptoJS.enc.Utf8);
	}

	//Show the result:
	$('#outputBox').text(result);
}

//Enter key binding:
$(document).ready(function(){
	$('#passwordBox').keypress(function(e){
		if(e.keyCode == 13){
			$('#submitButton').click();
		}
	});
	$('#passwordReenterBox').keypress(function(e){
		if(e.keyCode == 13){
			$('#submitButton').click();
		}
	});
});