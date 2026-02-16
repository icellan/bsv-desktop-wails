export namespace main {
	
	export class FileResult {
	    success: boolean;
	    path?: string;
	    error?: string;
	    canceled?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new FileResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.path = source["path"];
	        this.error = source["error"];
	        this.canceled = source["canceled"];
	    }
	}
	export class ManifestProxyResult {
	    status: number;
	    headers: string[][];
	    body: string;
	
	    static createFrom(source: any = {}) {
	        return new ManifestProxyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.headers = source["headers"];
	        this.body = source["body"];
	    }
	}

}

