[HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user == null)
            {
                return Unauthorized(new Response { Status = "Error", Message = "Invalid username or password." });
            }

            // Check if the entered password is correct
            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginModel.Password);

            if (!isPasswordValid)
            {
                return Unauthorized(new Response { Status = "Error", Message = "Invalid username or password." });
            }

            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                       await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                       var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                       var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
                       _emailService.SendEmail(message);

             }
            return StatusCode(StatusCodes.Status200OK,
                 new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });


        }