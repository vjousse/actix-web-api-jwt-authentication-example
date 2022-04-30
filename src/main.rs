use actix_web::dev::ServiceRequest;
use actix_web::{get, middleware, post, web, App, Error, HttpResponse, HttpServer, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::extractors::bearer::Config;
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;

use actix_web_api_jwt_authentication::auth_extractor::BearerUserAuth;

async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    eprintln!("{:?}", credentials);
    if credentials.token() == "hardcoded" {
        Ok(req)
    } else {
        let config = req
            .app_data::<Config>()
            .map(|data| data.clone())
            .unwrap_or_else(Default::default);

        Err(AuthenticationError::from(config)
            .with_error_description("Bad token")
            .into())
    }
}

#[get("/")]
async fn hello(credentials: BearerUserAuth) -> impl Responder {
    eprintln!("Hello {:?}", credentials);
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    eprintln!("Launching web server");
    HttpServer::new(|| {
        let auth_middleware = HttpAuthentication::bearer(validator);
        App::new()
            .wrap(middleware::Logger::default())
            //.wrap(auth_middleware)
            .service(hello)
            .service(echo)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
