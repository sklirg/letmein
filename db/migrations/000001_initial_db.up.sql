--
-- PostgreSQL database dump
--

-- Dumped from database version 12.4
-- Dumped by pg_dump version 12.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: claims; Type: TABLE; Schema: public; Owner: lmi
--

CREATE TABLE public.claims (
    user_id integer NOT NULL,
    site_id integer NOT NULL
);


ALTER TABLE public.claims OWNER TO lmi;

--
-- Name: sites; Type: TABLE; Schema: public; Owner: lmi
--

CREATE TABLE public.sites (
    id integer NOT NULL,
    url text NOT NULL
);


ALTER TABLE public.sites OWNER TO lmi;

--
-- Name: sites_id_seq; Type: SEQUENCE; Schema: public; Owner: lmi
--

CREATE SEQUENCE public.sites_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.sites_id_seq OWNER TO lmi;

--
-- Name: sites_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: lmi
--

ALTER SEQUENCE public.sites_id_seq OWNED BY public.sites.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: lmi
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    password text NOT NULL,
    salt text DEFAULT ''::text NOT NULL,
    admin boolean DEFAULT false NOT NULL
);


ALTER TABLE public.users OWNER TO lmi;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: lmi
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO lmi;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: lmi
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: sites id; Type: DEFAULT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.sites ALTER COLUMN id SET DEFAULT nextval('public.sites_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: claims claims_unique_user_url; Type: CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_unique_user_url UNIQUE (user_id, site_id);


--
-- Name: sites id_site; Type: CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT id_site PRIMARY KEY (id);


--
-- Name: users id_user; Type: CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT id_user PRIMARY KEY (id);


--
-- Name: sites url_unique; Type: CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT url_unique UNIQUE (url);


--
-- Name: users username_unique; Type: CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT username_unique UNIQUE (username);


--
-- Name: claims claims_site_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_site_id_fkey FOREIGN KEY (site_id) REFERENCES public.sites(id);


--
-- Name: claims claims_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: lmi
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

