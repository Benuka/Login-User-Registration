using Login.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Login.Controllers
{
    public class UserController : Controller
    {
        //Registratin Action
        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }

        //Registration POST action
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude = "IsEmailVerified,ActivationCode")]User user)
        {
            bool Status = false;
            string message = "";
            //
            //Model Validation
            if(ModelState.IsValid)
            {
                #region//Email already exist or not
                var isExist = IsEmailExist(user.EmailID);
                if(isExist)
                {
                    ModelState.AddModelError("EmailExist", "Email Already Exist");
                    return View(user);
                }
                #endregion
                //Generate Activation Code
                #region Generate Activation Code
                user.ActivationCode = Guid.NewGuid();
                #endregion

                //Password Hashing
                #region Password Hashing
                user.Password = Crypto.Hash(user.Password);
                user.ConfirmPassword = Crypto.Hash(user.ConfirmPassword);
                #endregion
                user.IsMailVerified = false;

                //Save data to database
                #region Save to Database
                using (MyDatabseEntities1 dc = new MyDatabseEntities1())
                {
                    dc.Users.Add(user);
                    dc.SaveChanges();

                    //send Email to user
                  // sendVerificationLinkEmail(user.EmailID , user.ActivationCode.ToString());
                    message = "Registration Successfully Done. Account Activation Link" +
                        "has been sent to your email" + user.EmailID;
                    Status = true;
                }
                #endregion


            }
            else
            {
                message = "Invalid Request";
            }

            return View(user);
        }

        //verify account
        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;
            using (MyDatabseEntities1 dc = new MyDatabseEntities1())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; //this line i have added to avoid 
                                                                // confirm password does not match issue on save changes
                var v = dc.Users.Where(a => a.ActivationCode == new Guid(id)).FirstOrDefault();
                if (v != null)
                {
                    v.IsMailVerified = true;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
            }
            ViewBag.Status = Status;
            return View();
        }

        //Login
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }


        //login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserLogin login, string ReturnUrl = "")
        {
            string message = "";
            using (MyDatabseEntities1 dc = new MyDatabseEntities1())
            {
                var v = dc.Users.Where(a => a.EmailID == login.EmailID).FirstOrDefault();
                if (v != null)
                {
                    if (string.Compare(Crypto.Hash(login.Password),v.Password) == 0)
                    {
                        int timeout = login.RememberMe ? 525600 : 1; //525600 min for 1 year
                        var ticket = new FormsAuthenticationTicket(login.EmailID, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);

                        if(Url.IsLocalUrl(ReturnUrl))
                        {
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            RedirectToAction("Index", "Home");
                        }
                    }
                    else
                    {
                        message = "Invalid Credential Provided";
                    }
                }
            }

            ViewBag.Message = message;
            return View();
        }


        //logout
        [Authorize]
        [HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }


        //verify Email
        [NonAction]
        public bool IsEmailExist(string emailID)
        {
            using (MyDatabseEntities1 dc = new MyDatabseEntities1())
            {
                var v = dc.Users.Where(a => a.EmailID == emailID).FirstOrDefault();
                return v != null;
            }
        }

        //Verify Email Link
        [NonAction]
        public void sendVerificationLinkEmail(string emailID, string activationCode)
        {

            var verifyUrl = "/User/VerifyAccount" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress("benuka02@gmail.com", "Dotnet Awsome"); //reblace with your email ID
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = "**********";//replace with your email password
            string subject = "Your Account is Successfully Created";

            string body = "<br/><br/>We are Excited to say that your account is Successfully Created. Please click on the below link to confirm Email"
                            + "<br/><br/><a href = '" + link + "'>" + link + "</a>";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
                smtp.Send(message);
            
        }
    }
}