import sys
import jwt
import httpx
import os
import json
import subprocess
#### import shutil
from typing import List
from pathlib import Path
#### import random
 
#### import pandas as pd
#### import matplotlib.pyplot as plt

from datetime import datetime, timedelta, date

from dotenv import load_dotenv
load_dotenv(override=True)  


# The following three lines allow for dropping embed() in to block and present an IPython shell
from IPython import embed
import nest_asyncio

nest_asyncio.apply()

import difflib

def get_clean_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

os.makedirs("logs", exist_ok=True)

import logging
from logging.handlers import RotatingFileHandler


def setup_logging():
    # uvicorn to capture logs from all libs
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Define the log file name with a timestamp
    log_filename = f"logs/slim_goodie_{get_clean_timestamp()}.log"

    # Stream handler (to console)
    c_handler = logging.StreamHandler()
    c_handler.setLevel(logging.INFO)

    # File handler (to file, with rotation)
    f_handler = RotatingFileHandler(log_filename, maxBytes=10485760, backupCount=5)
    f_handler.setLevel(logging.INFO)

    # Common log format
    formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d"
    )
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)


setup_logging()


from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Request,
    Response,
    Form,
    Query,
    File,
    UploadFile,
    BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyCookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from starlette.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware


from jinja2 import Environment, FileSystemLoader
from collections import defaultdict
from datetime import datetime, timedelta


from auth.supabase.connection import create_supabase_client


BASE_DIR = Path("./served_data").resolve()  # Base directory for serving files

# local udata prefernces
UDAT_FILE = "./etc/udat.json"
# Create if not exists
os.makedirs(os.path.dirname(UDAT_FILE), exist_ok=True)
if not os.path.exists(UDAT_FILE):
    with open(UDAT_FILE, "w") as f:
        json.dump({}, f)

# Initialize Jinja2 environment
templates = Environment(loader=FileSystemLoader("templates"))

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/templates", StaticFiles(directory="templates"), name="templates")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
app.mount("/tmp", StaticFiles(directory="tmp"), name="tmp")


# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key="your-secret-key")

# Serve static files
cookie_scheme = APIKeyCookie(name="session")
SKIP_AUTH = False if len(sys.argv) < 3 else True


class AuthenticationRequiredException(HTTPException):
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(status_code=401, detail=detail)


class MissingSupabaseEnvVarsException(HTTPException):
    def __init__(self, message="The Supabase environment variables are not found."):
        super().__init__(status_code=401, detail=message)


def proc_udat(email):
    with open(UDAT_FILE, "r+") as f:
        user_data = json.load(f)
        if email not in user_data:
            user_data[email] = {"style_css": "static/skins/slim_goodie.css", "email": email}

            f.seek(0)
            json.dump(user_data, f, indent=4)
            f.truncate()

    return user_data[email]


async def DELis_instance(value, type_name):
    return isinstance(value, eval(type_name))


def get_well_color(quant_value):
    # Transition from purple to white
    if quant_value <= 0.5:
        r = int(128 + 127 * (quant_value / 0.5))  # From 128 to 255
        g = int(0 + 255 * (quant_value / 0.5))  # From 0 to 255
        b = int(128 + 127 * (quant_value / 0.5))  # From 128 to 255
    # Transition from white to green
    else:
        r = int(255 - 255 * ((quant_value - 0.5) / 0.5))  # From 255 to 0
        g = 255
        b = int(255 - 255 * ((quant_value - 0.5) / 0.5))  # From 255 to 0

    return f"rgb({r}, {g}, {b})"


def highlight_json_changes(old_json_str, new_json_str):
    try:
        old_json = json.loads(old_json_str)
        new_json = json.loads(new_json_str)
    except json.JSONDecodeError:
        return old_json_str, new_json_str
    
    old_json_formatted = json.dumps(old_json, indent=2)
    new_json_formatted = json.dumps(new_json, indent=2)
    
    diff = difflib.ndiff(old_json_formatted.splitlines(), new_json_formatted.splitlines())
    
    old_json_highlighted = []
    new_json_highlighted = []
    
    for line in diff:
        if line.startswith("- "):
            old_json_highlighted.append(f'<span class="deleted">{line[2:]}</span>')
        elif line.startswith("+ "):
            new_json_highlighted.append(f'<span class="added">{line[2:]}</span>')
        elif line.startswith("  "):
            old_json_highlighted.append(line[2:])
            new_json_highlighted.append(line[2:])
    
    return '\n'.join(old_json_highlighted), '\n'.join(new_json_highlighted)


async def get_relationship_data(obj):
    relationship_data = {}
    for relationship in obj.__mapper__.relationships:
        if relationship.uselist:  # If it's a list of items
            relationship_data[relationship.key] = [
                {
                    "child_instance_euid": (
                        rel_obj.child_instance.euid
                        if hasattr(rel_obj, "child_instance")
                        else []
                    ),
                    "parent_instance_euid": (
                        rel_obj.parent_instance.euid
                        if hasattr(rel_obj, "parent_instance")
                        else []
                    ),
                    "euid": rel_obj.euid,
                    "uuid": rel_obj.uuid,
                    "polymorphic_discriminator": rel_obj.polymorphic_discriminator,
                    "super_type": rel_obj.super_type,
                    "btype": rel_obj.btype,
                    "b_sub_type": rel_obj.b_sub_type,
                    "version": rel_obj.version,
                }
                for rel_obj in getattr(obj, relationship.key)
            ]
        else:  # If it's a single item
            rel_obj = getattr(obj, relationship.key)
            relationship_data[relationship.key] = [
                (
                    {
                        "child_instance_euid": (
                            rel_obj.child_instance.euid
                            if hasattr(rel_obj, "child_instance")
                            else []
                        ),
                        "parent_instance_euid": (
                            rel_obj.parent_instance.euid
                            if hasattr(rel_obj, "parent_instance")
                            else []
                        ),
                        "euid": rel_obj.euid,
                        "uuid": rel_obj.uuid,
                        "polymorphic_discriminator": rel_obj.polymorphic_discriminator,
                        "super_type": rel_obj.super_type,
                        "btype": rel_obj.btype,
                        "b_sub_type": rel_obj.b_sub_type,
                        "version": rel_obj.version,
                    }
                    if rel_obj
                    else {}
                )
            ]
    return relationship_data


class RequireAuthException(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=403, detail=detail)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    file_path = os.path.join("static", "favicon.ico")
    return FileResponse(file_path)


@app.exception_handler(AuthenticationRequiredException)
async def authentication_required_exception_handler(
    request: Request, exc: AuthenticationRequiredException
):
    return RedirectResponse(url="/login")


async def require_auth(request: Request):

    if (
        os.environ.get("SUPABASE_URL", "NA") == "NA"
        and os.environ.get("SUPABASE_KEY", "NA") == "NA"
    ):
        msg = "SUPABASE_* env variables not not set.  Is your .env file missing?"
        logging.error(msg)

        raise MissingSupabaseEnvVarsException(msg)

    if "user_data" not in request.session:
        raise AuthenticationRequiredException()
    return request.session["user_data"]


@app.exception_handler(RequireAuthException)
async def auth_exception_handler(_request: Request, _exc: RequireAuthException):
    # Redirect the user to the login page
    return RedirectResponse(url="/login")


#
#  The following are the mainpage / index and auth routes for the application
#


@app.get("/", response_class=HTMLResponse)
async def read_root(
    request: Request,
):

    count = request.session.get("count", 0)
    count += 1
    request.session["count"] = count

    template = templates.get_template("index.html")
    user_data = request.session.get("user_data", {})
    style = {"skin_css": user_data.get("style_css", "static/skins/slim_goodie.css")}
    context = {"request": request, "style": style, "udat": user_data}

    return HTMLResponse(content=template.render(context), status_code=200)


@app.get("/login", include_in_schema=False)
async def get_login_page(request: Request):

    user_data = request.session.get("user_data", {})
    style = {"skin_css": user_data.get("style_css", "static/skins/slim_goodie.css")}

    # Ensure you have this function defined, and it returns the expected style information
    template = templates.get_template("login.html")
    # Pass the 'style' variable in the context
    context = {"request": request, "style": style, "udat": user_data, "supabase_url": os.getenv("SUPABASE_URL", "SUPABASE-URL-NOT-SET") } 
    return HTMLResponse(content=template.render(context))


@app.post("/oauth_callback")
async def oauth_callback(request: Request):
    body = await request.json()
    access_token = body.get("accessToken")

    if not access_token:
        return "No access token provided."
    # Attempt to decode the JWT to get email
    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        primary_email = decoded_token.get("email")
    except jwt.DecodeError:
        primary_email = None

    # Fetch user email from GitHub if not present in decoded token
    if not primary_email:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await client.get(
                "https://api.github.com/user/emails", headers=headers
            )
            if response.status_code == 200:
                emails = response.json()
                primary_email = next(
                    (email["email"] for email in emails if email.get("primary")), None
                )
            else:
                raise HTTPException(
                    status_code=400, detail="Failed to retrieve user email from GitHub"
                )

    # Check if the email domain is allowed
    whitelist_domains = os.getenv("SUPABASE_WHITELIST_DOMAINS", "all")
    if len(whitelist_domains) == 0:
        whitelist_domains = "all"
    if whitelist_domains.lower() != "all":
        allowed_domains = [domain.strip() for domain in whitelist_domains.split(",")]
        user_domain = primary_email.split("@")[1]
        if user_domain not in allowed_domains:
            raise HTTPException(status_code=400, detail="Email domain not allowed")

    request.session["user_data"] = proc_udat(
        primary_email
    )  # {"email": primary_email, "style_css": "static/skins/slim_goodie.css"}

    # Redirect to home page or dashboard
    return RedirectResponse(url="/", status_code=303)


@app.post("/login", include_in_schema=False)
async def login(request: Request, response: Response, email: str = Form(...)):
    # Use a static password for simplicity (not recommended for production)
    password = "notapplicable"
    # Initialize the Supabase client
    supabase = create_supabase_client()

    if not email:
        return JSONResponse(
            content={"message": "Email is required"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    with open(UDAT_FILE, "r+") as f:
        user_data = json.load(f)
        if email not in user_data:
            # The email is not in udat.json, attempt to sign up the user
            auth_response = supabase.auth.sign_up(
                {"email": email, "password": password}
            )
            if "error" in auth_response and auth_response["error"]:
                # Handle signup error
                return JSONResponse(
                    content={"message": auth_response["error"]["message"]},
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            else:
                pass  # set below via proc_udat
        else:
            # The email exists in udat.json, attempt to sign in the user
            auth_response = supabase.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            if "error" in auth_response and auth_response["error"]:
                # Handle sign-in error
                return JSONResponse(
                    content={"message": auth_response["error"]["message"]},
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

    # Set session cookie after successful authentication, with a 60-minute expiration
    response.set_cookie(
        key="session", value="user_session_token", httponly=True, max_age=3600, path="/"
    )
    request.session["user_data"] = proc_udat(email)
    # Redirect to the root path ("/") after successful login/signup
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    # Add this line at the end of the /login endpoint


@app.get(
    "/logout"
)  # Using a GET request for simplicity, but POST is more secure for logout operations
async def logout(request: Request, response: Response):

    try:
        logging.warning(f"Logging out user: Clearing session data:  {request.session}")

        # Initialize the Supabase client
        supabase = create_supabase_client()

        # Get the user's access token
        access_token = request.session.get("user_data", {}).get("access_token")

        if access_token:
            # Call the Supabase sign-out endpoint
            headers = {"Authorization": f"Bearer {access_token}"}
            async with httpx.AsyncClient() as client:
                logging.debug(f"Logging out user: Calling Supabase logout endpoint")
                response = await client.post(
                    os.environ.get("SUPABASE_URL", "NA") + "/auth/v1/logout",
                    headers=headers,
                )
                logging.debug(f"Logging out user: Supabase logout response: {response}")
                if response.status_code != 204:
                    logging.error("Failed to log out from Supabase")

        # Clear the session data
        request.session.clear()

        # Debug the session to ensure it's cleared
        logging.warning(f"Session after clearing: {request.session}")

        # Optionally, clear the session cookie.
        # Note: This might not be necessary if your session middleware automatically handles it upon session.clear().
        response.delete_cookie(key="session", path="/")

    except Exception as e:
        logging.error(f"Error during logout: {e}")
        return JSONResponse(
            content={"message": "An error occurred during logout: " + str(e)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Redirect to the homepage
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request, _auth=Depends(require_auth), dest="na"):

    os.makedirs(os.path.dirname(UDAT_FILE), exist_ok=True)
    if not os.path.exists(UDAT_FILE):
        with open(UDAT_FILE, "w") as f:
            json.dump({}, f)

    dest_section = {"section": dest}

    user_data = request.session.get("user_data", {})

    csss = []
    for css in sorted(os.popen("ls -1 static/skins/*css").readlines()):
        csss.append(css.rstrip())

    printer_info = {
        "print_lab": '',
        "printer_name": '',
        "label_zpl_style": '',
        "style_css": csss,
    }
    csss = [
        "static/skins/" + os.path.basename(css) for css in csss
    ]  # Get just the file names

    printer_info["style_css"] = csss
    style = {"skin_css": user_data.get("style_css", "static/skins/slim_goodie.css")}

    # Rendering the template with the dynamic content
    content = templates.get_template("admin.html").render(
        style=style,
        user_logged_in=True,
        user_data=user_data,
        printer_info=printer_info,
        dest_section=dest_section,
        udat=request.session["user_data"],
    )

    return HTMLResponse(content=content)


# Take a look at this later
@app.post("/update_preference")
async def update_preference(request: Request, auth: dict = Depends(require_auth)):
    # Early return if auth is None or doesn't contain 'email'
    if not auth or "email" not in auth:
        return {
            "status": "error",
            "message": "Authentication failed or user data missing",
        }

    data = await request.json()
    key = data.get("key")
    value = data.get("value")

    if not os.path.exists(UDAT_FILE):
        return {"status": "error", "message": "User data file not found"}

    with open(UDAT_FILE, "r") as f:
        user_data = json.load(f)

    email = request.session.get("user_data", {}).get("email")
    if email in user_data:
        user_data[email][key] = value
        with open(UDAT_FILE, "w") as f:
            json.dump(user_data, f)

        request.session["user_data"][key] = value
        return {"status": "success", "message": "User preference updated"}
    else:
        return {"status": "error", "message": "User not found in user data"}

#
#  The following are the main routes for the application
#


@app.get("/user_home", response_class=HTMLResponse)
async def user_home(request: Request):

    user_data = request.session.get("user_data", {})
    session_data = request.session.get("session_data", {})  # Extract session_data from session


    if not user_data:
        return RedirectResponse(url="/login")

    # Directory containing the CSS files
    skins_directory = "static/skins"
    css_files = [f"{skins_directory}/{file}" for file in os.listdir(skins_directory) if file.endswith(".css")]

    style = {"skin_css": user_data.get("style_css", "static/skins/slim_goodie.css")}
    dest_section = request.query_params.get("dest_section", {"section": ""})  # Example value

        
    printer_info = {
        "print_lab": '',
        "printer_name": '',
        "label_zpl_style": '',
        "style_css": css_files,
    }


    # Fetching version details
    github_tag = subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
    setup_py_version = subprocess.check_output(["python", "setup.py", "--version"]).decode().strip()
    fedex_version = os.popen("pip freeze | grep fedex_tracking_day | cut -d = -f 3").readline().rstrip()  
    zebra_printer_version = os.popen("pip freeze | grep zebra-day | cut -d = -f 3").readline().rstrip()  

    # HARDCODED THE BUCKET PREFIX INT to 0 here and elsewhere using the same pattern.  Reconsider the zero detection (and prob remove it)
    content = templates.get_template("user_home.html").render(
        request=request,
        user_data=user_data,
        session_data=session_data,  # Pass session_data to template
        css_files=css_files,
        style=style,
        dest_section=dest_section,
        whitelisted_domains=" , ".join(os.environ.get("SUPABASE_WHITELIST_DOMAINS", "all").split(",")), 
        s3_bucket_prefix=os.environ.get("NANANA", "NEEDS TO BE SET!")+"0",
        supabase_url=os.environ.get("SUPABASE_URL", "NEEDS TO BE SET!"),
        printer_info=printer_info,
        github_tag=github_tag,
        setup_py_version=setup_py_version,
        fedex_version=fedex_version,
        zebra_printer_version=zebra_printer_version,
        udat=user_data
    )
    return HTMLResponse(content=content)

@app.get("/http_serve_endpoint/{file_path:path}", response_class=HTMLResponse)
async def serve_files(file_path: str, request: Request, auth=Depends(require_auth)):
    print('YYYYYYYYY',file_path)
    
    #file_path = "/"+ file_path.replace('//','/').lstrip('/').rstrip('/').lstrip('/') 
    #if file_path == "" or file_path =="//":
    #    file_path="/"

    if file_path.startswith('/'):
        file_path = file_path.lstrip('/')

    if  file_path in [None,"","/"]:
        file_path = ""
    print('RRRRR',file_path)

        
    requested_path = BASE_DIR / file_path
    print('xxxxxx', BASE_DIR, file_path, requested_path)
    logging.info(f"Requested path: {requested_path}")
    
    if not requested_path.exists():
        logging.error(f"File or directory not found: {requested_path}")
        raise HTTPException(status_code=404, detail="File or directory not found")

    full_path = requested_path.resolve()

    if full_path.is_dir():
        return directory_listing(full_path, file_path)
    elif full_path.is_file():
        if full_path.suffix == '.html':
            with open(full_path, 'r') as f:
                content = f.read()
            return HTMLResponse(content=content)
        return FileResponse(full_path, media_type="application/octet-stream", filename=full_path.name)

    raise HTTPException(status_code=404, detail="File or directory not found")


def directory_listing(directory: Path, file_path: str) -> HTMLResponse:
    """
    Generate an HTML response listing the contents of a directory with alphabetical ordering.
    """

    parent_path = file_path + "/../.."
    
    # Alphabetical sort for directories and files
    items = sorted(directory.iterdir(), key=lambda x: x.name.lower())

    files = []
    for item in items:
        if item.is_dir():
            files.append(
                f'<li><a href="/http_serve_endpoint/{file_path.lstrip('/')}/{item.name}/">{item.name}/</a></li>'
            )
        else:
            files.append(
                f'<li><a href="/http_serve_endpoint/{file_path.lstrip('/')}/{item.name}">{item.name}</a></li>'
            )
    print('PPPPPP', str(parent_path))
    html_content = f"""
    <h2>Directory listing for: {directory.name}</h2>
    <ul>
        <li><a href="/http_serve_endpoint/{parent_path.lstrip('/')}">.. (parent directory)</a></li>
        {''.join(files)}
    </ul>
    """
    return HTMLResponse(content=html_content)

# Middleware for checking authentication
@app.get("/protected_content", response_class=HTMLResponse)
async def protected_content(request: Request, auth=Depends(require_auth)):
    """
    Example of an endpoint requiring authentication.
    Once authenticated, users can access protected resources.
    """
    content = "You are authenticated and can access protected resources."
    return HTMLResponse(content=content)
