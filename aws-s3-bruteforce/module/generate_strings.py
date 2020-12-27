#!/usr/bin/env python
from lib.constants import *

def get_string_variations(string, prefix_postfix_option, acronyms_only_option):
    #Names are not case sensitive
    string = string.lower()

    #Remove junk chars that can't be in the bucket name, e.g & , "
    names = remove_junk_chars(string)

    #All all sorts of variations of the name
    add_with_no_entity(names)
    names = add_acronyms(names, acronyms_only_option)
    add_with_space_replacements(names)
    if prefix_postfix_option is not None:
        add_with_prefix_postfix_domains(names, prefix_postfix_option)

    #Get the sorted set of names
    names = sorted(list(set(names)))

    #Return the names
    return names

def load_permutations(filename, prefix_postfix_option, acronyms_only_option):
    names = []
    with open( filename ) as f:
        names = [line.rstrip('\n') for line in f]
    # Remove junk chars that can't be in the bucket name, e.g & , "
    clean_names = []
    for n in names:
        clean_names += remove_junk_chars( n )

    # All all sorts of variations of the name
    add_with_space_replacements( names )

    # Get the sorted set of names
    names = sorted( list( set( names ) ) )

    #Return the names
    return names

def remove_junk_chars(string):
    """Remove characters that shouldn't or won't be in a bucket name"""
    name = string
    names = []

    #Remove junk chars
    junk_chars = ["'", '"', "&#39;", "!"]
    for junk_char in junk_chars:
        name = name.replace(junk_char, "")

    #Remove domains (this can be added later)
    domains = [".com", ".org", ".net", ".edu", ".gov"]
    for domain in domains:
        name = name.replace(domain, "")

    #Replace junk char with space so it can be replaced by a replacement char
    name = name.replace(","," ")
    name = name.replace("."," ")
    name = name.replace("&", " and ")

    #Remove any duplicate spaces
    while "  " in name:
        name = name.replace("  ", " ")

    #Add the name without "and" if it's there (e.g. "Bob & Sue" becomes "Bob and Sue" and "Bob Sue")
    names.append(name.strip())
    if " and " in name:
        names.append(name.replace(" and ", " ").strip())
    return names


def add_acronyms(names, acronyms_only_option):
    acronyms = []

    chomped_strings = []
    for name in names:
        if len(name.split()) > 1:
            if name.startswith("the "):
                new_name = name.replace("the ","")
                if new_name not in chomped_strings:
                    chomped_strings.append(new_name)
                    acronyms.append(get_abbreviated_string(new_name))
            acronyms.append(get_abbreviated_string(name))
    #Before going any further, be sure there aren't repeats to save memeory
    acronyms = list(set(acronyms))

    if acronyms_only_option:
        if acronyms:
            return acronyms
        else:
            return names
    else:
        names.extend(acronyms)
        return names


def get_abbreviated_string(name):
    abbreviated_string = ""
    for word in name.split():
        abbreviated_string += word[0]
    return abbreviated_string


def add_with_no_entity(names):
    """If an entity name, e.g. Inc. or Corp., is in the name, add the name without it"""
    chomped_names = []
    for name in names:
        for entity in entities:
            if entity in name:
                chomped_names.append(rchop(name, entity).strip())
    names.extend(chomped_names)


def add_with_space_replacements(names):
    """Replaces every space in the line with replacements, e.g. -,_, and null"""
    space_replaced_names = []
    names_to_remove = []

    for name in names:
        if " " in name:
            for space_replacement in space_replacements:
                space_replaced_names.append(name.replace(" ",space_replacement).strip())
            names_to_remove.append(name)

    #Remove all instances of names with spaces
    for name_to_remove in names_to_remove:
        while name_to_remove in names:
            names.remove(name_to_remove)

    names.extend(space_replaced_names)


def add_with_prefix_postfix_domains(names, prefix_postfix_option):
    '''For every name varient, add prefixes and postfixes, e.g. dev, www, .com, etc
       Don't add prefix+postfix or you'll end up with internal-site-dev
    '''
    names_with_additions = []
    for name in names:
        #Add prefixes and postixes, SEPARATE so you don't get things like dev.site-internal
        for prefix_postfix in prefixes_postfixes:
            for prefix_postfix_separator in prefix_postfix_separators:
                if prefix_postfix_option == "prefix" or prefix_postfix_option == "both":
                    names_with_additions.append("{prefix_postfix}{prefix_postfix_separator}{name}".format(prefix_postfix=prefix_postfix, prefix_postfix_separator=prefix_postfix_separator, name=name))     
                if prefix_postfix_option == "postfix" or prefix_postfix_option == "both":
                    names_with_additions.append("{name}{prefix_postfix_separator}{prefix_postfix}".format(name=name, prefix_postfix_separator=prefix_postfix_separator, prefix_postfix=prefix_postfix))

        #Only add domains if none of them are in the string yet
        if not any(domain in name for domain in domains):
            for domain in domains:
                names_with_additions.append("{name}{domain}".format(name=name, domain=domain))
                names_with_additions.append("www.{name}{domain}".format(name=name, domain=domain))
                for prefix_postfix in prefixes_postfixes:
                    for prefix_postfix_separator in prefix_postfix_separators:
                        #Add as a prefix
                        if prefix_postfix_option == "prefix" or prefix_postfix_option == "both":
                            names_with_additions.append("{prefix_postfix}{prefix_postfix_separator}{name}{domain}".format(prefix_postfix=prefix_postfix, prefix_postfix_separator=prefix_postfix_separator, name=name, domain=domain))
                            names_with_additions.append("{prefix_postfix}{prefix_postfix_separator}www.{name}{domain}".format(prefix_postfix=prefix_postfix, prefix_postfix_separator=prefix_postfix_separator, name=name, domain=domain))
                        #Add as a postfix
                        if prefix_postfix_option == "postfix" or prefix_postfix_option == "both":
                            names_with_additions.append("{name}{domain}{prefix_postfix_separator}{prefix_postfix}".format(name=name, domain=domain, prefix_postfix_separator=prefix_postfix_separator, prefix_postfix=prefix_postfix))
                            names_with_additions.append("www.{name}{domain}{prefix_postfix_separator}{prefix_postfix}".format(name=name, domain=domain, prefix_postfix_separator=prefix_postfix_separator, prefix_postfix=prefix_postfix))
    names.extend(names_with_additions)


def rchop(thestring, ending):
    """Removes the given ending from the end of the string"""
    if thestring.endswith(ending):
        return thestring[:-len(ending)]
    return thestring